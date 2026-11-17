# PEGM10 内核提权尝试 · 最终报告

目标设备：OPPO Reno5 K 5G（`PEGM10` / `OP4E59`）
系统：ColorOS `V13.1.0` / Android 13（SDK 33）/ `user` build / 国行 `CN01`
内核：`4.19.157-perf+`，编译于 2025-06-12，clang 10.0.7
安全补丁：**2025-06-01**
平台：Qualcomm lito（SM7250/7350），Adreno 619，aarch64

---

## 一、结论速览

| 路线 | 状态 | 阻塞点 |
|---|---|---|
| 公开 CVE 直接利用 | ❌ 全部失效 | SPL 2025-06 + 内核 2025-06 编译 |
| Bootloader 解锁 | ❌ 固件层封死 | ABL 忽略 `bootloader`/`bootonce-bootloader` 指令 |
| kgsl（GPU 驱动） | 🟡 部分可达 | `DRAWCTXT_CREATE` 全 EINVAL；CPU mmap 受限（存疑，见下） |
| binder | 🟡 部分可达 | 裸 ioctl 发 `BC_*` 命令返回 EINVAL |
| OPPO 厂商节点 | ❌ 全 SELinux 拒 | — |

**整体判定：本机在公开利用面上已无可用路径，需要自行发现新的内核漏洞。**

---

## 二、环境加固面（实测配置）

| 配置项 | 值 | 影响 |
|---|---|---|
| `CONFIG_USER_NS` | 未设置 | `unshare -U` → `EINVAL`，依赖 userns 的利用全废 |
| `CONFIG_NF_TABLES` | 未编译 | nf_tables 整族 CVE 无攻击面 |
| `CONFIG_VSOCKETS` | 未设置 | vsock 系 UAF 无入口 |
| io_uring | 4.19 无此子系统 | io_uring 系全废 |
| `CONFIG_STATIC_USERMODEHELPER` | `y`，`PATH=""` | `modprobe_path` 覆盖后无任何程序执行 |
| `CONFIG_SLAB_FREELIST_HARDENED` | `y` | 堆喷门槛高 |
| `CONFIG_HARDENED_USERCOPY` | `y`（含 PAGESPAN） | 跨堆/跨栈拷贝被拦 |
| `CONFIG_KASAN` | 未开 | 崩溃即 oops，无检测兜底 |
| shell 进程 seccomp | `0` | 系统调用不受限 |
| SELinux | `Enforcing`，`u:r:shell:s0` | — |

---

## 三、Bootloader：确认封死

| 入口 | 结果 |
|---|---|
| 音量下 + 电源 | 进 ColorOS Recovery，非 fastboot |
| `adb reboot bootloader` | ABL 收到 `bootreason=bootloader`，**仍冷启动系统** |
| `adb reboot bootonce-bootloader` | 同上，被忽略 |
| `adb reboot fastboot` | ✅ 进入 **fastbootd**（userspace） |
| fastbootd 内 `fastboot reboot bootloader` | ABL 忽略，回系统 |

fastbootd 实测：`is-userspace=yes`、`unlocked=no`、`secure=yes`、`slot-count=0`。
**fastbootd 不支持任何解锁命令**：`flashing get_unlock_ability` / `flashing unlock` / `oem device-info` 全部 `Unrecognized command` 或 `Unable to open fastboot HAL`。

关键分区：`devinfo` = sde27，`oplus_sec` = sde26，`oplusdycnvbk` = sdf2，`vbmeta` = sde18，`abl` = sde8。

---

## 四、kgsl（Adreno 619）攻击面

### 4.1 可达性

| 操作 | 结果 |
|---|---|
| `open("/dev/kgsl-3d0")` | ✅（`crw-rw-rw-`，shell 域放行） |
| `ioctl` 分发 | ✅ 命令级无限制 |
| `KGSL_GPUMEM_ALLOC_ID`(0x34) | ✅ 成功，返回 `id` / `gpuaddr=0x500000000` |
| `KGSL_GPUOBJ_ALLOC`(0x45) | ✅ 成功，返回 `id=1` / `mmapsize=0x1000` |
| `KGSL_GPUMEM_GET_INFO`(0x36) | ✅ 成功，返回 `mmap_offset` |
| `mmap` | ⚠️ 见 4.4 更正 |
| `KGSL_DRAWCTXT_CREATE`(0x13) | ❌ 穷举 32 种 context type 全 `EINVAL` |

### 4.2 ioctl 表枚举（95 个 nr）

用 `mkelf_scan.py` 遍历 nr `0x01..0x5F`，完整映射见 `kgsl-ioctl-map.md`。重点：

| nr | 零参数返回值 | 备注 |
|---|---|---|
| `0x49` | `EFAULT` | 解引用 struct 内指针，喂真实指针后变 `EINVAL` |
| `0x5B` | `EFAULT` | 同上，喂真实指针后变 **`EAGAIN`(11)** → 读取类接口 |
| `0x50`–`0x55` | `ENOMEM` | 六个连号，全走分配层 |
| `0x3B` | `EPERM` | 全表唯一权限拒绝 |

### 4.3 关键操作记录

`KGSL_GPUMEM_ALLOC_ID` 完整返回（1 MB 申请）：

```
id        = 1
flags     = 0x000C0000
size      = 0x100000
mmapsize  = 0x100000
gpuaddr   = 0x0000000500000000
```

`KGSL_DEVICE_GETPROPERTY(DEVICE_INFO)` 返回：

```
+0  0x00000001    device_id
+4  0x06010900    chip_id  = Adreno 619
+8  0x00000100    mmu_enabled
```

### 4.4 kgsl 的 mmap 确实被拒（已复核）

`mkelf_chain.py` 单进程链：`open` → `GPUMEM_ALLOC_ID` → `GET_INFO` → `mmap`，用阶段标记输出：

```
$ /data/local/tmp/kgslchain
ABC                 # A=open B=alloc C=get_info 全部通过
exit=243            # 256-243 = 13 = EACCES，卡在 mmap
```

**该链的 mmap 长度是从 `GET_INFO` 返回的 `size` 字段读回来的真实值（`0x100000`），不是硬编码**，
因此不存在第六节所述的立即数截断问题。**kgsl 的 `EACCES` 是可信结论。**

对比 binder：同机 binder 的 mmap 在 1 MB 尺寸下**成功**。说明：

- SELinux 对 `gpu_device` 允许 `ioctl`，但拒绝 `mmap`（返回 `EACCES`）
- SELinux 对 `binder_device` 的 `mmap` 放行

这是两个子系统在策略上的差异，不是工具缺陷。

---

## 五、binder 攻击面

### 5.1 设备与协议

```
/dev/binder   -> /dev/binderfs/binder    （shell 可 open）
/dev/hwbinder -> /dev/binderfs/hwbinder  （shell 可 open）
/dev/vndbinder                           （SELinux 拒绝）
```

| 指标 | 结果 |
|---|---|
| `BINDER_VERSION` | **8**（完整实现） |
| `BINDER_SET_MAX_THREADS` | rc = 0 |
| `BINDER_WRITE_READ`（空 BWR） | rc = 0 |
| **`BINDER_SET_CONTEXT_MGR`** | **`EBUSY`(16)** → 命令真的执行了，位置已被 servicemanager 占用 |
| `mmap`（1 MB / 1 MB-8K / 4 KB，PROT_READ + MAP_PRIVATE） | ✅ **全部成功** |

### 5.2 决定性对照：libbinder 能发事务

| 命令 | 结果 |
|---|---|
| `service call iphonesubinfo 1` | ✅ 返回 `Parcel(...)` |
| `service call activity 1` | ✅ 返回完整 Parcel |
| `service call nosuchservice 1` | 正确报「服务不存在」 |

**`service` 走 libbinder，能正常发事务。而我们的裸 ioctl 客户端不能。**

### 5.3 裸 ioctl 的阻塞点

只要 `write_size > 0`，`BINDER_WRITE_READ` 就返回 `EINVAL` 且 `write_consumed = 0`：

| BC 命令 | 值 | 结果 |
|---|---|---|
| `BC_ENTER_LOOPER` | `0x0c` | `EINVAL`，consumed=0 |
| `BC_REGISTER_LOOPER` | `0x0b` | `EINVAL`，consumed=0 |
| `BC_EXIT_LOOPER` | `0x0d` | `EINVAL`，consumed=0 |
| `BC_TRANSACTION` | `0x00` | `EINVAL`，consumed=0 |

`write_size` 取 4 / 8 / 16 结果一致；加 `read_size`+`read_buffer` 也一致；
去掉 mmap 也一致。

结构体已 dump 验证完全正确：`write_size=4`、`write_buffer` 指向有效栈地址、
缓冲内容 `0c 00 00 00`、`read_size=0`。

`EINVAL` + `consumed=0` 在语义上对应 `binder_thread_write` 的 `default:` 分支（**未知命令**），
但命令值 `0x0c` 就是 `BC_ENTER_LOOPER`，矛盾未解。

### 5.4 未解之谜与后续方向

| 假设 | 状态 |
|---|---|
| mmap 尺寸/prot 导致 | ❌ 已排除 |
| `cmd` 常量算错 | ❌ 已排除（空 BWR 返回 0） |
| 结构体尺寸不符 | ❌ 已排除（48 正确） |
| `write_size` 语义歧义 | ❌ 已排除（4/8/16 一致） |
| 厂商在 `binder_thread_write` 入口硬化 | 🟡 待验证 |
| SELinux `ioctl` xperm 白名单 | 🟡 待验证（但通常会返回 EPERM） |

---

## 六、工具链（本项目的实际产出）

环境里**没有可用的交叉编译器**（NDK 下载速率 ~0.03 MB/s，镜像 0.02 MB/s，均不可行），
因此全部探针用 **纯 Python 手搓 ARM64 机器码 + 手工构造 ELF** 实现，零依赖、零下载。

| 文件 | 用途 |
|---|---|
| `mkelf.py` | 最小 open+ioctl+exit，用退出码回传达 errno |
| `mkelf_call.py` | 通用 ioctl 调用器（任意请求号 + 结构体字段表，支持 `sp` 指针值） |
| `mkelf_scan.py` | ioctl 表枚举器（循环 nr 1..0x5F） |
| `mkelf_ctx.py` | context type 穷举器 |
| `mkelf_full.py` | 带完整 `kgsl_device_getproperty` 的读数探针 |
| `mkelf_alloc.py` | `GPUMEM_ALLOC_ID` 合法调用 |
| `mkelf_chain.py` | 单进程 alloc→getinfo→mmap 全链，带 A/B/C/D 阶段标记 |
| `mkelf_binder.py` | binder 可达性 + mmap 参数扫描 |
| `mkelf_binder_txn.py` | binder 事务构造器（支持 `--hex` / `--wsize` / `--withread` / `--nommap`） |
| `mkelf_binder_cmd.py` | 通用 binder ioctl 探测器 |
| `crashlog.ps1` | 崩溃日志抓取（bugreport → `last_kmsg`） |

### 关键教训：movz 立即数截断

```python
def movz64(rd, imm16, shift=0):        # 错误用法：直接传入大数值
    return ... ((imm16 & 0xFFFF) << 5) ...
```

`movz` 只能装载 16 位立即数。直接传 `131072` 会被 `& 0xFFFF` 截成 **0**，
导致 mmap 的长度参数变成 0，返回 `EINVAL`，被误判为「内核拒绝了 mmap」。

**正确做法**：用 `movz` + `movk` 链装载任意 64 位常量（各脚本中已提供的 `load_const`）。

这个 bug 曾导致 binder 的 mmap 结论完全错误，凡是「mmap 被拒」的结论都需用修正后的工具复测。

---

## 七、崩溃日志通道（已验证可用）

本机内核日志通道几乎全关：

| 通道 | 状态 |
|---|---|
| `dmesg` | ❌ `dmesg_restrict` |
| `/proc/kmsg`、`/dev/kmsg` | ❌ 权限拒绝 |
| `/proc/last_kmsg` | ❌ 不存在 |
| `/sys/fs/pstore` | ❌ SELinux |
| `/cache/recovery/*` | ❌ SELinux |
| `logcat -b kernel` | ❌ 缓冲区恒为 0 字节 |
| **`adb bugreport` → `FS/cache/recovery/last_kmsg*`** | ✅ **唯一可用** |

`last_kmsg` 内容格式：`<级别>[时间戳] (CPU)[PID:进程名]内容`，含完整启动过程与 `Call trace`。
`crashlog.ps1` 已封装「触发崩溃 → 重启 → 抓取 → 扫关键字」全流程。

顺带从日志挖到 kgsl 的 IOMMU 拓扑：

```
iommu: Adding device 3d40000.qcom,kgsl-iommu:gfx3d_user   to group 29
iommu: Adding device 3d40000.qcom,kgsl-iommu:gfx3d_secure to group 30
```

---

## 八、下一步建议（按性价比排序）

1. **深入 kgsl 的 `DRAWCTXT_CREATE`（0x13）**。这是 kgsl 路线上唯一剩下的硬阻塞：
   拿不到 context 就发不了 `GPU_COMMAND`。需要确认 EINVAL 是来自 context 类型校验、
   还是 OPPO 在 `kgsl_context_create` 里加了准入条件（可用 `last_kmsg` 观察内核打印）。
2. **深入 `0x5B`**：`EAGAIN` 表明它是读取类接口，数据结构未知，值得逆向。
   也值得试 `0x49`（喂真实指针后变 `EINVAL`，说明已进入参数校验）。
3. **kgsl 的 `mmap` 已有定论（`EACCES`）**，若要走 GPU 命令投递路线，
   `GPUOBJ_IMPORT` + `GPU_COMMAND` 是不依赖 CPU 映射的替代方案——前提是先解决 context。
4. **binder 的 `EINVAL`**：需要对照 OPPO 定制 binder 源码，或从 `last_kmsg` 里找
   `pr_err("%d:%d unknown command %d")` 的内核打印，确认是否命中 `default` 分支。
5. 若上述均不通，则本机只能等新漏洞。

---

## 九、最终判断

这台机器在**公开漏洞面上已经清零**：SPL 2025-06 抹掉了所有已知 Android 内核提权，
bootloader 在固件层焊死，厂商节点全锁。

真正的机会只剩**自己挖掘**，而目前最有希望的两个方向是：

- **kgsl**：权限最宽（`crw-rw-rw-`）、ioctl 完全开放、历史漏洞最多，且刚发现「mmap 其实可能可用」这一反转。
- **binder**：协议完整、libbinder 可正常发事务，但裸 ioctl 的写路径有未解之谜。

**建议优先回头复测 kgsl**——如果 mmap 与 context 两处都是工具 bug 造成的假象，
整条链可能本来就是通的。

---

## 十、root 进程与 binder 服务面（补充探测）

### 10.1 以 root 身份运行的用户态进程

```
root  739  vold
root  936  netd
root  1134 android.hardware.thermal@2.0-service.qti
root  1136 android.hardware.usb@1.2-service-qti
root  1149 vendor.qti.hardware.perf@2.2-service
root  1179 vendor-oplus-hardware-performance-V1-service
root  1193 vendor-oplus-hardware-touch-V1-service
root  1241 vendor.oplus.hardware.olc2-V1-service
root  1255 vendor.oplus.hardware.wifi@1.1-service
root  1732 atlasservice
root  1764 mmlistservice
root  1831 poweropt-service
root  1897 vendor-oplus-hardware-engineer-V1-service
```

这些进程是**真正的 uid 0**。若能使其崩溃或执行任意代码，即为 root。

### 10.2 系统登记的 binder 服务总数

`service list` → **330 个**。其中 OPPO 私有服务占很大比例：

```
AtlasService / ISubsysRadio / MMListService / OPLUSExService
OplusLocationManager / additionald / anti_root_dialog
app_compatibility / athenaservice / channel_service
color_screenshot / dynamic_filter / engineer / heimdall
hephaestus_app_data_service / horae / midasd / multimediaDaemon
neuronsystem / obrain / olc / onetrace / oplus_*（约 30 个）
```

注意 `anti_root_dialog`（反 root 提示）的存在，说明 OPPO 有专门的 root 检测与对抗组件。

### 10.3 `engineer` 服务（IOplusEngineerManager）接口测绘

```bash
service check engineer          # found
service call engineer N
```

| code | 返回（field2） | 判定 |
|---|---|---|
| 1, 2, 4, 6, 8, 9, 10, 14 | `ffffffff` (-1) | 存在，返回失败/需参数 |
| 3, 5, 7, 11, 12, 15 | `00000000` (0) | 存在，无参即成功 |
| **13** | 返回单一字段 `00000000` | 返回值结构不同 |
| **16 及以上** | `ffffffff fffffb6` (-74) | **未实现的 transaction code** |

结论：`IOplusEngineerManager` 对外暴露 **15 个 transaction code**。

### 10.4 副作用验证

调用 3 / 5 / 7 / 11 / 12 / 15 前后对比系统状态：

| 项 | 调用前 | 调用后 |
|---|---|---|
| `getenforce` | Enforcing | Enforcing |
| `ro.debuggable` | 0 | 0 |
| `ro.secure` | 1 | 1 |
| `ro.boot.verifiedbootstate` | green | green |

**无任何状态变化**，这些方法在本机是只读或无副作用的。

### 10.5 字符串参数测试

`service call engineer 1 s16 <4000 个 A>` → 正常返回 `ffffffff`，无崩溃。
原因：`service call` 的参数经 libbinder 序列化，parcel 结构始终合法，
**打不到 AIDL 解析层的边界问题**。要触达实现层逻辑，必须精确匹配方法签名。

### 10.6 root HAL 服务不可直接调用

```
dumpsys -l 中：
  engineer                                            ← Java AIDL，在 system_server
  vendor.oplus.hardware.engineer.IEngineer/default    ← AIDL HAL，在 root 进程 1897

service check "vendor.oplus.hardware.engineer.IEngineer/default"   → found
service call  "vendor.oplus.hardware.engineer.IEngineer/default" 1 → does not exist
```

`check` 认、`call` 不认。说明 `service call` 的查找路径与 `check` 不同，
带 `/` 的 AIDL HAL 实例名无法通过这条命令调用。

**要打这个 root HAL，必须自己写 AIDL 客户端**（需要知道接口的 transaction code 布局），
或者经由 `engineer` Java 服务间接调用。

## 十一、总体结论

经过完整测绘，本机的提权路径收敛为：

| 路径 | 状态 | 阻塞 |
|---|---|---|
| 公开内核 CVE | 死 | SPL 2025-06 |
| Bootloader 解锁 | 死 | ABL 固件层删除了 fastboot 映射 |
| kgsl CPU mmap | 死 | SELinux 对 `gpu_device` 的 `mmap` 返回 EACCES |
| kgsl context | 死 | `DRAWCTXT_CREATE` 全 EINVAL（编码已逐条核对无误） |
| binder 裸 ioctl 写 | 死 | `BC_*` 命令一律 EINVAL，consumed=0 |
| OPPO proc 节点 | 死 | SELinux 全拒 |
| `service call` fuzz | 受限 | libbinder 序列化保证 parcel 合法，打不到解析层 |
| root HAL 服务 | **未打通** | `service call` 调不了带 `/` 的实例名 |

**剩下的唯一实质方向：自己实现 AIDL 客户端，直连 root 进程的 HAL，寻找实现层漏洞。**
这需要逆向 `vendor-oplus-hardware-engineer-V1-service` 二进制，还原其 transaction code 布局，
再针对参数校验做定向测试。工作量以周计，且不保证有结果。

**这台机器在"用现成方法提权"这个意义上，已经走到尽头。**

---

## 十二、binder 写路径的最后一轮排除

### 12.1 已排除的假设（完整清单）

| # | 假设 | 实验方法 | 结果 |
|---|---|---|---|
| 1 | mmap 未建立 | 先 mmap 再写 | ❌ 仍 EINVAL |
| 2 | mmap 尺寸不足 | 4K / 128K / 1M / 1M-8K | ❌ 与尺寸无关 |
| 3 | mmap prot 错误 | PROT_READ / READ+WRITE | ❌ 无关 |
| 4 | `cmd` 常量算错 | 同值空 BWR 返回 0 | ❌ 常量正确 |
| 5 | 结构体尺寸不符 | 扫 size 8..127 | ❌ 48 已被空调用证明正确 |
| 6 | `write_size` 语义歧义 | 4 / 8 / 16 三种 | ❌ 全部 EINVAL |
| 7 | 缺少 `read_size` | 同时设置 read_size+read_buffer | ❌ 仍 EINVAL |
| 8 | 缺少初始化序列 | 补 `BINDER_VERSION` + `SET_MAX_THREADS` | ❌ 仍 EINVAL |
| 9 | 命令字不被识别 | 扫 0x00/0x0b/0x0c/0x0d | ❌ 全部 EINVAL，consumed=0 |
| 10 | 栈页不可读 | **改用 mmap 匿名页作写缓冲** | ❌ 仍 EINVAL |
| 11 | SELinux 域不同 | `ps -Z` 对比 | ❌ shell 与 system_server 域均正常，libbinder 可通 |

### 12.2 关键对照

| 主体 | 路径 | BC 命令结果 |
|---|---|---|
| `service`（libbinder） | shell 域 → system_server | ✅ 成功收发 Parcel |
| 我们的裸 ELF | shell 域 → 裸 ioctl | ❌ `EINVAL`，`write_consumed=0` |
| `BINDER_SET_CONTEXT_MGR` | 裸 ioctl（非 BC 类） | ✅ `EBUSY`（业务语义，命令已执行） |

**非 BC 类的写 ioctl 全部正常，只有 `binder_thread_write` 的 BC 命令通道被拒。**

`EINVAL` + `consumed=0` 精确对应 `binder_thread_write` 的 `default:` 分支（未知命令），
但命令字与 `BC_ENTER_LOOPER` 完全一致，逻辑上矛盾。

### 12.3 判定

这是**厂商定制行为**，非通用 Android 行为。可能的实现方式：

- OPPO 在 binder 驱动里检测「非 libbinder 客户端」并拒绝（例如检查特定的 proc 状态位）
- 或对 `binder_thread_write` 的前置条件做了额外校验

**要绕过这个限制，必须拿到本机 binder 驱动的源码或二进制做逆向。**
在拿到之前，任何自写 binder 客户端（包括访问 root HAL 的 AIDL 客户端）都无法工作。

