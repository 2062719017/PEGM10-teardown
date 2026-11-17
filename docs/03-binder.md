# binder 攻击面探测结果（PEGM10 / Android 13）

设备：OPPO Reno5 K 5G · Android 13 / SDK 33 · `u:r:shell:s0` / uid 2000
探测工具：`mkelf_binder.py`（ARM64 静态 ELF，零编译依赖）

## 一、设备与挂载

```
lrwxrwxrwx 1 root root u:object_r:binder_device:s0   /dev/binder   -> /dev/binderfs/binder
lrwxrwxrwx 1 root root u:object_r:hwbinder_device:s0 /dev/hwbinder -> /dev/binderfs/hwbinder
lrwxrwxrwx 1 root root u:object_r:vndbinder_device:s0 /dev/vndbinder -> /dev/binderfs/vndbinder

binder on /dev/binderfs type binder (rw,relatime,max=1048576,stats=global)
```

`/dev/binder` 与 `/dev/hwbinder` 均可从 shell 直接 `open()`；`/dev/vndbinder` 被 SELinux 拒绝。

## 二、协议层探测结果

`BINDER_VERSION` 与 `BINDER_WRITE_READ` 均正常响应：

| 指标 | `/dev/binder` | `/dev/hwbinder` |
|---|---|---|
| `open(O_RDWR)` | ✅ | ✅ |
| `BINDER_VERSION` | **8** | **8** |
| `BINDER_WRITE_READ`（全零结构） | rc = 0 | rc = 0 |

协议版本 8 与 Android 13 的 binder 驱动一致，说明这不是裁剪版实现。

## 三、mmap 参数扫描（关键）

binder 必须 `mmap` 才能承载 parcel 缓冲区。对 size / prot / flags 做组合扫描：

| 用例 | size | prot | flags | 结果 |
|---|---|---|---|---|
| bm1 | 131072 (128K) | `PROT_READ`(1) | `MAP_PRIVATE`(2) | ❌ `EINVAL`(22) |
| bm2 | 131072 | `PROT_READ`(1) | `MAP_SHARED`(1) | ❌ `EINVAL`(22) |
| **bm3** | **4096** | **`PROT_READ`(1)** | **`MAP_PRIVATE`(2)** | **✅ 成功** |
| bm4 | 131072 | `PROT_READ\|PROT_WRITE`(3) | `MAP_SHARED`(1) | ❌ `EINVAL`(22) |
| bm5 | 1048576 (1M) | `PROT_READ`(1) | `MAP_PRIVATE`(2) | ❌ `EINVAL`(22) |

### 结论

- **恰好一页（4096 字节）的映射可以成功**，更大尺寸一律 `EINVAL`。
- 与 `prot` / `MAP_*` 类型无关——写权限不是原因（`PROT_READ` 的 128K 同样失败）。
- 这不是 SELinux 拒绝（那会是 `EACCES`），而是尺寸相关。

### 影响

一页的 binder 缓冲区只有 4096 字节，binder 事务头 `binder_transaction_data` 本身约 40 字节，剩余空间足以承载：

- 小型 `BC_TRANSACTION`（含少量数据）
- 服务查询 / `BC_ACQUIRE` / `BC_RELEASE` / `BC_ENTER_LOOPER` 等控制命令
- 畸形 parcel 测试（越界长度字段、嵌套 fd 数组等）

## 四、OPPO 专有节点（反向排除）

| 路径 | 结果 |
|---|---|
| `/proc/oplus_ke/force_shutdown` | `Permission denied` |
| `/proc/oplus_secure_common/*` | `Permission denied` |
| `/proc/oplusVersion/{test,ocp,cdt,RFType,engVersion,oplusBootmode,pcbVersion,prjName,serialID,isConfidential,feature}` | 全部 `Permission denied` |
| `/proc/oplus_rf/rf_cable` | `Permission denied` |
| `/proc/oplus_scheduler/sched_assist` | `Permission denied` |
| `/proc/oplus_healthinfo` | `Permission denied` |

这些节点的 DAC 是 `dr-xr-xr-x root:root`（理论上 others 可读），但 SELinux 标签（`proc` / `proc_oppo_secure_common_file` / `oplus_healthinfo_proc`）对 `shell` 域全部闭门。
**厂商节点这条线对 shell 不可用**，除非先拿到更高权限的域。

## 五、三条路线横向对比

| 路线 | 可达性 | 阻塞点 | 后续可做 |
|---|---|---|---|
| **kgsl** | 分配 ✅ / ioctl ✅ / import ✅ | `mmap` EACCES；`DRAWCTXT_CREATE` 全 EINVAL | 审计 `0x49`/`0x5B` |
| **binder** | 协议 ✅ / 版本 8 ✅ / mmap ✅（4096） | 缓冲区仅一页 | 构造 `BC_TRANSACTION`，fuzz parcel 解析 |
| **OPPO 节点** | ❌ 全 SELinux 拒 | — | 需更高权限域才可触达 |

## 六、binder 方向的具体下一步

1. **构造最小 `BC_ENTER_LOOPER` + `BC_TRANSACTION`**，验证一页缓冲区足以完成一次完整事务往返。
2. **枚举可访问服务**：通过 `BC_TRANSACTION` 打 `servicemanager`（handle 0），调用 `listServices` / `getService`。shell 域本身有 `find`/`call` 权限时可见大量系统服务（`service list` 已验证可跑）。
3. **畸形 parcel 测试**：`binder_transaction_data.data_size` 与 `offsets_size` 的不一致、嵌套 `flat_binder_object` 的 fd 数组、`BC_FREE_BUFFER` 重复释放等，是 binder 驱动历史上 UAF/类型混淆的高发区。
4. 注意：本机 SPL 2025-06-01，公开的 binder CVE（CVE-2019-2215、CVE-2020-0041、CVE-2020-0423、CVE-2023-20938 等）均已修复，需要自己找新缺口。

## 七、复现命令

```powershell
# 生成探针
python mkelf_binder.py "/dev/binder" bp_main 4096 1 2

# 部署运行
adb push bp_main /data/local/tmp/bp_main
adb shell 'chmod 755 /data/local/tmp/bp_main; /data/local/tmp/bp_main > /data/local/tmp/b.bin'
adb pull /data/local/tmp/b.bin

# 输出 6 字节：[open_ok, binder_version, wr_rc, mmap_ok, mmap_errno, 0]
```

---

## 八、事务发送实验（write 路径异常）

### 8.1 三个基础 ioctl 全部可用

| 命令 | 值 | 结果 |
|---|---|---|
| `BINDER_VERSION` | `0xC0046209`（4B） | rc = 0，版本 **8** |
| `BINDER_SET_MAX_THREADS` | `0x40046205`（4B） | rc = 0 |
| `BINDER_WRITE_READ`（全零 BWR） | `0xC0306201`（48B） | rc = 0 |

说明 `ioctl` 分发完全正常，`cmd` 常量计算正确，48 字节的 `binder_write_read` 尺寸匹配。

### 8.2 一旦设置 write_size 就 EINVAL

构造一条无害的 `BC_ENTER_LOOPER`(0x0c)，并原样 dump 出送进内核的结构体：

```
status: 1 234 0 0        # mmap_ok=1, rc=0xEA(→ -22 EINVAL), write_consumed=0

binder_write_read:
  +0  : 04 00 00 00 00 00 00 00    write_size   = 4
  +8  : 00 00 00 00 00 00 00 00    write_consumed = 0
  +16 : 60 2e db d4 7f 00 00 00    write_buffer = 0x7ffdd4db2e60   （有效栈地址）
  +24 : 00 00 00 00 00 00 00 00    read_size    = 0
  +32 : 00 00 00 00 00 00 00 00
  +40 : 00 00 00 00 00 00 00 00

写缓冲首 8 字节:
  0c 00 00 00 00 00 00 00          BC_ENTER_LOOPER
```

**结构体完全正确，内核却返回 `EINVAL`，且 `write_consumed = 0`**（一个字节都没被消费）。

### 8.3 已排除的可能原因

| 假设 | 实验 | 结论 |
|---|---|---|
| mmap 影响 | 加 `--nommap` 跳过 mmap，直接发命令 | 仍 EINVAL，❌ 无关 |
| mmap 尺寸 | 4096 / 128K / 1M 都试过 | 只有 4096 能映射，但失败与尺寸无关 |
| prot / MAP_* 类型 | READ/SHARED/PRIVATE 组合 | 均 EINVAL，❌ 无关 |
| `cmd` 常量算错 | 同值全零 BWR 返回 0 | 常量正确，❌ 排除 |
| 结构体尺寸不匹配 | 扫描 size 8..127 全部 | 全 EINVAL，但 48 已被全零实验证明正确 |
| 写缓冲地址无效 | dump 出指针值，指向有效栈 | ✅ 地址有效 |

### 8.4 工具 bug（已修正）

首版 size 扫描器用 `movk w1, #0xC000, lsl #16` 覆盖高 16 位，而 `size` 字段正好位于 bits[29:16]，
导致 120 次扫描实际全是 `size=0`。已改为 `ORR w1, w1, w2, LSL #16`（`w2 = 0xC000 + size`）的正确构造。

### 8.5 结论与后续

**异常点**：`BC_ENTER_LOOPER` 是 binder 里最简单、无参数、不可能失败的写命令（`binder_thread_write`
里只是置一个 looper 标志位），但本机内核返回 `EINVAL` 且不消费任何字节。

可能解释（待验证）：

1. **厂商对 `binder_thread_write` 加了前置校验**（OPPO 定制 binder 驱动），非特权上下文发写命令直接拒。
2. **SELinux `ioctl` xperm 细化**：Android 支持 `allowxperm` 按命令号放行 ioctl，未列出的命令被策略层拦下（但通常报文为 `EPERM`，这里是 `EINVAL`，语义不符）。
3. **`binder_write_read` 在本内核更大**（例如 56 字节），而 size=48 恰好命中了另一个分支。

**下一步**：从 `/proc/kallsyms` 角度不可行（受限），改为在 `last_kmsg` 里找 binder 相关的启动日志，
或者用 `dumpsys`/`logcat` 观察 `binder_ioctl_write_read` 是否有 debug 输出；也可以尝试
`BINDER_SET_CONTEXT_MGR` 等其它写类 ioctl，看是否同样被拒，以判断是「所有写路径」还是「仅 BC 命令」。

### 8.6 关键对照：SET_CONTEXT_MGR 返回 EBUSY

| ioctl | 值 | 返回 | 说明 |
|---|---|---|---|
| `BINDER_VERSION` | `0xC0046209` | rc=0，版本 8 | 分发正常 |
| `BINDER_SET_MAX_THREADS` | `0x40046205` | rc=0 | 分发正常 |
| `BINDER_WRITE_READ`（空） | `0xC0306201` | rc=0 | 分发正常 |
| **`BINDER_SET_CONTEXT_MGR`** | `0x40046207` | **`EBUSY`(16)** | **命令被执行了**，只是位置已被占用 |

`EBUSY` 是 binder 驱动在 `binder_new_node` 之后发现 `context_mgr_node` 已存在时返回的**正常业务错误**，
不是拒绝。这证明：

1. 非 `BC_*` 的写类 ioctl **完全能抵达驱动内部并执行**；
2. 拒绝只发生在 `binder_thread_write` 处理 `BC_*` 命令这一层。

于是问题范围被压缩到：**「为什么 `binder_thread_write` 连 `BC_ENTER_LOOPER` 都拒绝」**。

### 8.7 待验证假设（按可能性排序）

1. **`write_buffer` 指向的内存页不可被内核直接读**：`binder_thread_write` 用 `get_user()` 从用户态取命令字，
   若该页被视为不可读（例如栈页被 `HARDENED_USERCOPY` 或 binder 自己的校验拦下），会返回 `-EFAULT`，
   但本机报的是 `-EINVAL`，语义不符——除非 OPPO 改了返回值。
2. **厂商在 `binder_thread_write` 前加了 looper 状态校验**：要求先通过某个厂商私有 ioctl 注册线程。
3. **`binder_thread_write` 的 `size` 语义被改**：某些定制品把 `write_size` 解释为「命令条数」而非字节数。
   若按条数解释，`write_size=4` 会试图读 4 条命令，第一条之后越界 → 可能返回 `EINVAL`。

**验证方案**：把写缓冲改成 8 字节并放两条 `BC_ENTER_LOOPER`（`0c 00 00 00 0c 00 00 00`），
`write_size` 分别试 4 和 8。若 8 通过而 4 不通过，则假设 3 成立。

### 8.8 BC 命令字全扫结果

对 `BC_TRANSACTION(0x00)` 与三个**无参数**的 looper 命令做对照，全部落在同一结果上：

| BC 命令 | 值 | 结果 | write_consumed |
|---|---|---|---|
| `BC_ENTER_LOOPER` | `0x0c` | `EINVAL`(22) | 0 |
| `BC_REGISTER_LOOPER` | `0x0b` | `EINVAL`(22) | 0 |
| `BC_EXIT_LOOPER` | `0x0d` | `EINVAL`(22) | 0 |
| `BC_TRANSACTION` | `0x00` | `EINVAL`(22) | 0 |

同时把 `write_size` 分别设为 4 / 8 / 16（写缓冲里放 1、2、4 条 `BC_ENTER_LOOPER`）：

| write_size | 结果 | write_consumed |
|---|---|---|
| 4 | `EINVAL` | 0 |
| 8 | `EINVAL` | 0 |
| 16 | `EINVAL` | 0 |

**这否定了「write_size 被解释为条数」的假设**（假设 3 不成立）。

### 8.9 最终定位

证据链收束到一点：**只要 `write_size > 0`，`BINDER_WRITE_READ` 就返回 `EINVAL` 且不消费任何字节；
而 `write_size = 0` 时返回 0。** 且 `SET_CONTEXT_MGR` 能返回业务语义的 `EBUSY`，证明驱动本体工作正常。

指向的结论：**本机内核在 `binder_thread_write` 入口处对来自该进程的写请求做了拒绝**，
拒绝发生在解析任何 BC 命令之前。这与上游 binder 的行为不一致，属于厂商定制或策略层硬化。

工作假设（下一步验证）：OPPO 可能要求通过 libbinder 的正常路径（`ProcessState::self()->startThreadPool()`）
建立 `binder_proc` 后才允许写，或者对 `binder_device` 的 ioctl 做了 xperm 白名单，
把 `BINDER_WRITE_READ` 之外的行为统一收敛为 `EINVAL`。

**验证手段**：用 `service call` 或 `cmd` 这类厂商自带的 binder 客户端观察是否能发事务（它们走 libbinder，
理应成功），若能成功则证明限制只针对「裸 ioctl 客户端」，属于路径检测而非权限缺失。

