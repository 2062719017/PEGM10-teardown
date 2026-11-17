# KGSL ioctl 表枚举结果（PEGM10 / msm-4.19.157-perf+）

设备：OPPO Reno5 K 5G（`PEGM10`）· 内核 `4.19.157-perf+` · Android 13 / SPL 2025-06-01
发起者：adb shell（uid 2000，`u:r:shell:s0`）· 设备节点：`/dev/kgsl-3d0`

## 枚举方法

`mkelf_scan.py` 生成的 292 字节 ARM64 ELF，对 `nr = 0x01 .. 0x5F` 依次调用：

```
ioctl(fd, _IOWR(0x09, nr, 32), zerobuf32)
```

每个 nr 向 stdout 写 2 字节（`nr`, `返回值低 8 位`），共 190 字节。

## errno 语义

| raw | errno | 含义 | 判定 |
|---|---|---|---|
| `00` | 0 | 成功 | 命令有效且零参数即通过 |
| `E7` | 25 | `ENOTTY` | **nr 未注册** |
| `EA` | 22 | `EINVAL` | 已注册，参数/状态被拒 |
| `ED` | 19 | `ENODEV` | 已注册，属性/设备无效 |
| `A1` | 95 | `EOPNOTSUPP` | 已注册，本平台不支持 |
| `F2` | 14 | `EFAULT` | 已注册，且处理器解引用了 struct 内的用户指针 |
| `F4` | 12 | `ENOMEM` | 已注册，分配失败（零参数下） |
| `FF` | 1 | `EPERM` | 已注册，权限拒绝 |

## 已注册的命令（非 ENOTTY）

| nr | errno(零参) | 备注 / 已知行为 |
|---|---|---|
| `0x02` | ENODEV | `KGSL_DEVICE_GETPROPERTY`，实测 `type=1` 时 `rc=0`，能读回 devinfo |
| `0x07` | EINVAL | 时间戳类 |
| `0x10` | EINVAL | `RINGBUFFER_ISSUEIBCMDS` |
| `0x13` | EINVAL | `DRAWCTXT_CREATE`，**各种 flags 与尺寸组合均 EINVAL** |
| `0x14` | EINVAL | `DRAWCTXT_DESTROY` |
| `0x15` | EOPNOTSUPP | `MAP_USER_MEM`，本机不实现 |
| `0x16` | EINVAL | 共享内存类 |
| `0x17` | EINVAL | 共享内存类 |
| `0x20` | EOPNOTSUPP | 本机不实现 |
| `0x21` | EINVAL | — |
| `0x24` | EINVAL | 时间戳读 |
| `0x2F` | EINVAL | `GPUMEM_ALLOC`（旧接口） |
| `0x32` | ENODEV | 同步/属性类 |
| `0x33` | EINVAL | 旧分配接口 |
| `0x34` | EINVAL | **`GPUMEM_ALLOC_ID`**，正确参数下 `rc=0` ✅ |
| `0x35` | EINVAL | `GPUMEM_FREE_ID` |
| `0x36` | EINVAL | **`GPUMEM_GET_INFO`**，有效 id 下可用 ✅ |
| `0x37` | EINVAL | `GPUMEM_SYNC` |
| `0x38` | **0** | 零参数即成功（无操作语义） |
| `0x39` | **0** | 零参数即成功 |
| `0x3A` | **0** | 零参数即成功 |
| `0x3B` | **EPERM** | 权限拒绝，值得单独研究 |
| `0x3C` | EINVAL | — |
| `0x3D` | EINVAL | — |
| `0x40` | **0** | 零参数即成功 |
| `0x41` | **0** | 零参数即成功 |
| `0x42` | EINVAL | — |
| `0x43` | EINVAL | — |
| `0x45` | **0** | **`GPUOBJ_ALLOC`**，正确参数下返回 `id` ✅ |
| `0x46` | EINVAL | `GPUOBJ_FREE` |
| `0x47` | EINVAL | `GPUOBJ_INFO` |
| `0x48` | **ENOMEM** | `GPUOBJ_IMPORT`，零参数下走到分配层 |
| `0x49` | **EFAULT** | **解引用了 struct 内指针**，是重点审计对象 |
| `0x4A` | EINVAL | **`GPU_COMMAND`**，需有效 `context_id` |
| `0x4B` | EOPNOTSUPP | 本机不实现 |
| `0x4C` | EINVAL | `GPUOBJ_SYNC` |
| `0x50`–`0x55` | **ENOMEM** | 连续 6 个命令都走到分配层，成组存在 |
| `0x57` | EINVAL | — |
| `0x58` | **0** | 零参数即成功 |
| `0x59` | EINVAL | — |
| `0x5A` | EINVAL | — |
| `0x5B` | **EFAULT** | 同 `0x49`，解引用 struct 内指针 |
| `0x5C` | **0** | 零参数即成功 |
| `0x5D` | ENODEV | — |

未列出的 nr 全部返回 `ENOTTY`，即该位置没有注册处理函数。

## 关键结论

1. **`ioctl` 分发对 shell 完全开放**，没有任何 SELinux 层面的命令级限制。
2. **两条分配路径都可用**：`0x34`（GPUMEM_ALLOC_ID，旧接口）和 `0x45`（GPUOBJ_ALLOC，新对象接口）。
3. **`mmap` 是唯一被拦的一环**（`EACCES`），所以 CPU 侧无法直接读写 GPU 内存。
4. **`DRAWCTXT_CREATE`（0x13）持续 EINVAL**，导致 `GPU_COMMAND`（0x4A）拿不到 `context_id`。这是当前链路上唯一的硬阻塞。
5. **`0x49` 和 `0x5B` 返回 `EFAULT`**，说明它们的处理器会解引用 struct 里的用户指针——在零参数下就触发了 `copy_from_user`。这两个是最值得优先审计的目标：攻击面暴露得最彻底。
6. **`0x50`–`0x55` 六个连号命令都返回 `ENOMEM`**，说明这组接口都会走内存分配，成组出现通常意味着同一族功能（很可能是 GPU 对象/缓冲区相关的扩展接口）。

## 下一步

- 审计 `0x49` / `0x5B`：它们对 struct 内指针的校验逻辑是典型越界源。
- 攻 `DRAWCTXT_CREATE` 的 EINVAL：换更多 flags 组合，或确认 OPPO 是否在 `kgsl_context_create` 路径上加了额外校验。
- 若 context 拿不到，退而研究 `0x50`–`0x55` 这一族，它们不依赖 context。

---

## 第二轮：定向突破结果

### DRAWCTXT_CREATE（0x13）— 彻底不通

用 `mkelf_ctx.py` 穷举 `flags = type << 20`，`type = 0 .. 31`（覆盖 `KGSL_CONTEXT_TYPE_MASK` 全部取值）：

```
type= 0..31  ->  全部 errno=22 (EINVAL)
```

32 种类型、加上此前测过的 6 种结构体尺寸、4 组 flags 组合，**无一例外返回 EINVAL**。
结论：这个内核上 `DRAWCTXT_CREATE` 的路径被整体拒绝，与 `flags` 取值无关。
`GPU_COMMAND`(0x4A) 需要 `context_id`，因此这条路被硬阻塞。

### 0x50–0x55 族 — 当前状态无法突破

用 48 字节结构体、首字段填入 `size = 0x1000`：

```
nr=0x50..0x55  ->  全部 errno=12 (ENOMEM)，结构体未被回填
```

说明它们会在分配阶段失败。零参数与带 size 参数结果一致，暂时没有可用的推进方向。

### 0x49 / 0x5B — 有实质进展

关键实验：把结构体第 0 字段从 `NULL` 改成**指向结构体自身的有效栈指针**（`mkelf_call.py` 的 `sp` 特殊值）。
错误码随之变化，证明指针被真正解引用：

| nr | 指针 = NULL | 指针 = 有效地址 | 判定 |
|---|---|---|---|
| `0x49` | `EFAULT`(14) | **`EINVAL`(22)** | 指针解引用成功，进入参数合法性校验 |
| `0x5B` | `EFAULT`(14) | **`EAGAIN`(11)** | 指针解引用成功，属于读取类命令，当前无数据 |

`EAGAIN` 是「稍后重试」语义，典型于时间戳队列 / 事件读取接口。它暗示 `0x5B` 在数据就绪时会真正返回内容，是一个值得继续研究的目标。

### 当前阻塞点总结

| 环节 | 状态 |
|---|---|
| `open` / `ioctl` 分发 | ✅ 完全开放 |
| `GPUMEM_ALLOC_ID` / `GPUOBJ_ALLOC` | ✅ 可用 |
| `GPUMEM_GET_INFO` / `GPUOBJ_IMPORT` | ✅ 可调用 |
| `mmap` | ❌ `EACCES` |
| `DRAWCTXT_CREATE` | ❌ 穷举 32 类型全 `EINVAL` |
| `GPU_COMMAND` | ⛔ 缺 `context_id` |
| `0x50`–`0x55` | ❌ 全 `ENOMEM` |
| `0x49` / `0x5B` | 🟡 指针可达，参数待构造 |

