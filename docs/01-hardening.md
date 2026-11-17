# PEGM10 提权可行性评估

设备：OPPO Reno5 K 5G（`PEGM10` / `OP4E59`），ColorOS `V13.1.0`，Android 13（SDK 33），国行 `PEGM10_13.1.0.2101(CN01)`
序列号：`1ea0e2d9`　·　采集方式：adb（uid 2000，`u:r:shell:s0`）

---

## 1. 目标环境指纹

| 项 | 实测值 |
|---|---|
| 内核 | `4.19.157-perf+`，`#1 SMP PREEMPT`，编译于 **2025-06-12**，`clang 10.0.7 for Android NDK` |
| 平台 | lito（SM7250/7350 家族），aarch64，`ro.zygote=zygote64_32` |
| GPU | Adreno 619（`gpu_model`） |
| 安全补丁级别 | **2025-06-01** |
| Build 类型 | `user` / `release-keys` |
| SELinux | `Enforcing`，shell 上下文 `u:r:shell:s0` |
| Verified Boot | `green`，`ro.boot.flash.locked=1`，`veritymode=enforcing` |
| Bootloader 解锁 | `unlocked:no`（fastbootd `getvar all`） |
| adb 进程 seccomp | `Seccomp: 0`（shell 无 seccomp 过滤） |
| `NoNewPrivs` | `0` |
| 内存 | `MemTotal: 11651284 kB`，`MemAvailable: 8462524 kB` |

## 2. 内核编译配置（`/proc/config.gz`，6343 行，可读）

| 配置项 | 值 | 对提权的影响 |
|---|---|---|
| `CONFIG_USER_NS` | **未设置** | `unshare -U` 直接 `EINVAL`；所有依赖非特权 user namespace 的利用（nf_tables 系、绝大多数 2023 后的 LPE）全部失效 |
| `CONFIG_NF_TABLES` | **未编译** | netfilter nftables 整族 CVE（CVE-2024-1086、CVE-2023-32233 等）连攻击面都不存在 |
| `CONFIG_VSOCKETS` | **未设置** | vsock 系 UAF（CVE-2025-21756 一类）无入口 |
| io_uring | 4.19 分支无此子系统 | io_uring 系 CVE 不适用 |
| `CONFIG_STATIC_USERMODEHELPER` | `y`，`PATH=""` | usermode helper 被固定为单一空路径 → `modprobe_path` / `core_pattern` 覆盖后**不会执行任何用户态程序** |
| `CONFIG_SLAB_FREELIST_HARDENED` | `y` | freelist 指针混淆，堆喷成功率高要求高 |
| `CONFIG_SLAB_FREELIST_RANDOM` | `y` | 堆布局随机化 |
| `CONFIG_SLAB_MERGE_DEFAULT` | `y` | slab 合并开启（跨类型对象共池，利 exploiter） |
| `CONFIG_HARDENED_USERCOPY` | `y`（`FALLBACK=y`, `PAGESPAN=y`） | 跨栈/跨堆 slab 拷贝被拦 |
| `CONFIG_KASAN` | 未开 | 无额外检测，崩溃即 oops |
| `CONFIG_KALLSYMS` / `_ALL` / `_BASE_RELATIVE` | `y` / `y` / `y` | 符号表在，但 shell 侧 `kptr_restrict` 拦截 |
| `CONFIG_BPF_SYSCALL` | `y` | eBPF 可用（需 root/CAP_BPF 才能加载验证器程序） |
| `CONFIG_SECCOMP` / `_FILTER` | `y` | 内核支持，但 shell 进程未附加 |
| `CONFIG_ASHMEM` | `y` | ashmem 可用 |
| `CONFIG_ION` | `y`，但 `SYSTEM/CARVEOUT/CHUNK/CMA` 堆**全部未设置** | ion 基本空壳 |
| `CONFIG_DIAG_CHAR` / `DIAG_OVER_USB` | `y` / `y` | diag 字符设备存在（DAC 挡住 shell） |
| `CONFIG_MSM_RDBG` | `m` | 模块，未加载 |

## 3. 从 adb shell 可达的设备节点

测试方式：`open(O_RDWR)` + `read()`，逐节点验证。

| 节点 | 权限 / SELinux 标签 | shell 可达性 | 备注 |
|---|---|---|---|
| `/dev/kgsl-3d0` | `crw-rw-rw-` `u:object_r:gpu_device:s0` | **✅ 可 open、可 read** | Adreno 619 GPU；历史 LPE 密集区 |
| `/dev/binder` | `binderfs` 符号链接 | **✅ 可 open** | Binder 驱动本体 |
| `/dev/hwbinder` | `binderfs` 符号链接 | **✅ 可 open** | HWBinder |
| `/dev/ion` | `crw-rw-r--` `ion_device` | ✅ open OK（read `EINVAL`） | 堆配置几乎全关 |
| `/dev/ashmem` | `crw-rw-rw-` `ashmem_device` | ✅ 可 open | 匿名共享内存 |
| `/dev/msm_npu` | `crw-r--r--` `vendor_npu_device` | ✅ open OK | NPU 驱动 |
| `/dev/diag` | `crw-rw----` `system:vendor_qti_diag` | ❌ DAC 拒绝 | 不在 `vendor_qti_diag` 组 |
| `/dev/qseecom` | `crw-rw----` `system:drmrpc` | ❌ DAC 拒绝 | 不在 `drmrpc` 组 |
| `/dev/vndbinder` | `binderfs` | ❌ SELinux 拒绝 | shell 域无权限 |
| `/dev/binder_stats` | `crw-------` root | ❌ | |

`/sys/class/kgsl/kgsl-3d0/` 目录列表被拒，但单文件如 `gpu_model` 可读 → **sysfs 单文件粒度放行**。

## 4. "DirtyFrag" 名称核对

公开漏洞命名里，我能确认存在的是下列这一族，**没有找到叫 `DirtyFrag` 的公开利用**：

| 名称 | CVE | 影响内核 | 本机是否适用 |
|---|---|---|---|
| Dirty COW | CVE-2016-5195 | ≤ 4.8 | 否，4.19 早已修复 |
| Dirty Pipe | CVE-2022-0847 | 5.8 – 5.16.11 | 否，4.19 无此代码路径 |
| DirtyCred | —（技术手法） | 需已有 UAF 原语 | 需先有 UAF |
| Dirty Pagetable | —（技术手法，PTE 级 UAF 转任意读写） | 需已有 UAF | 需先有 UAF |
| Dirty Decrypt | —（PXN 绕过研究） | 需已有任意读 | 需先有读原语 |

`DirtyCred` / `Dirty Pagetable` 是**利用手法**而非独立漏洞：它们把「一个 UAF」升级成「任意内核读写」，前提是已经拿到 UAF。本机上没有任何已知可用的 UAF 入口（见第 5 节）。

如果 `DirtyFrag` 指的是某个 2025 年新公开的具体 bug，需要它的 affected-version 窗口才能判定；对 4.19 这种长期分支，OPPO 在 2025-06-12 的编译里做过后向移植，2025 年上半年的公开 CVE 大概率已被覆盖。

## 5. CVE 逐个判死

| CVE | 组件 | 需要 userns / CAP | 本机判定 |
|---|---|---|---|
| CVE-2019-2215 | binder UAF | 否 | 2018 年修复，不在 4.19.157 |
| CVE-2020-0041 | binder | 否 | 2020-03 修复 |
| CVE-2020-0423 | binder | 否 | 2020-10 修复 |
| CVE-2021-0920 | unix socket GC UAF | 否 | 2021-11 修复 |
| CVE-2023-20938 | binder UAF | 否 | 2023-02 修复 |
| CVE-2020-11201 / 11202 | kgsl | 否 | 2020 修复 |
| CVE-2021-1905 / 1940 / 1941 | kgsl | 否 | 2021 修复 |
| CVE-2022-22064 | kgsl | 否 | 2022 修复 |
| CVE-2024-1086 | nf_tables | 是 | `NF_TABLES` 未编译 → 无面 |
| CVE-2023-32233 | nf_tables | 是 | 同上 |
| CVE-2024-26925 / 36971 | netfilter | 视情况 | 同上 |
| CVE-2022-2588 / 2586 | cls_route / cls_fw | 是 | 依赖 userns → 无面 |
| CVE-2025-21756 | vsock | 否 | `VSOCKETS` 未编译 → 无面 |
| CVE-2024-0044 | run-as（framework） | 否 | 2024-03 修复；`user` build 无 debuggable |
| io_uring 全族 | — | — | 4.19 无该子系统 |

结论：**这台机器在公开 CVE 面上没有可用牌**。SPL 2025-06-01 + 2025-06-12 编译的内核，把所有 2024 年及以前公开的 Android 内核提权都吃掉了；而 2025 年新出的、能打 4.19 的公开利用，目前没有能落到 `4.19.157-perf+` OPPO 分支的。

## 6. 仍然活着的攻击面（研究入口）

按可达性排序：

1. **`/dev/kgsl-3d0`** — `crw-rw-rw-` 且 shell 域放行 open。Qualcomm Adreno 驱动是历史上 LPE 最高产的组件（2019–2023 至少 8 个可用漏洞）。可申请/释放 GPU 对象、mmap、投递 GPU 命令。**这是本机最值得审计的目标。**
2. **`/dev/binder` / `/dev/hwbinder`** — 协议解析面积巨大，`BC_*` 命令族与对象生命周期管理是 UAF 温床。
3. **`/dev/msm_npu`** — NPU 驱动，用户态可控的 IOMMU 映射区。
4. **`/dev/ashmem`** — 简单，历史漏洞已绝迹。
5. **OPPO 自有 `/proc/oplus_*`、`/sys/module/oplus_*`** — `oplus_ke`、`oplus_secure_common`、`oplus_fdleak_check` 一类厂商节点，属于非上游代码，审计密度低。

## 7. 探针程序

见同目录 `probe.c`。它做四件事：

1. 打印内核版本、uid、SELinux 上下文、`kptr_restrict` / `perf_event_paranoid`
2. 逐个 `open` 上述设备节点，输出 DAC/SELinux 裁决
3. 对 kgsl 执行 `GETPROPERTY(DEVICE_INFO)`、`GETPROPERTY(MMU_ENABLE)`、`GPUMEM_ALLOC_ID(1MB)`、`GPUMEM_GET_INFO`、`mmap`、`GPUMEM_FREE_ID`——验证「分配 + 映射 + 释放」整条原语链在 shell 权限下贯通
4. 对 binder 执行 `BINDER_VERSION`，确认 binder 协议版本

### 构建

```powershell
# 用 NDK r27c
$env:NDK = "$env:TEMP\android-ndk-r27c"
& "$env:NDK\toolchains\llvm\prebuilt\windows-x86_64\bin\clang.exe" `
  --target=aarch64-linux-android21 -O2 -static -o probe probe.c
```

### 部署与运行

```powershell
adb push probe /data/local/tmp/probe
adb shell chmod 755 /data/local/tmp/probe
adb shell /data/local/tmp/probe
```

## 8. 假如拿到了内核任意读写，落地路线

前提：已经有一段可信的内核读/写原语。之后按标准四步走：

1. **提权**：定位 `init_task` → 遍历 `task_struct.tasks` 找到当前进程 → 改写 `cred->uid/gid/euid/egid/suid/sgid/fsuid/fsgid` 为 0，并清 `securebits`。符号解析走 `ksymtab`（`CONFIG_KALLSYMS_BASE_RELATIVE=y` 时表项是 32 位相对偏移，配合 `CONFIG_KALLSYMS_ALL=y` 可定位所有非 static 符号）。
2. **关 SELinux**：改 `selinux_state.enforcing` 为 0，或直接把 `selinux_state` 的 `initialized` 置 0 让 policy 失效。`setenforce 0` 在 enforcing 下需要 root + policy 允许，先改内存更省事。
3. **绕过 AVB 的运行时影响**：解锁前 `vbmeta` 校验在启动期完成，运行期改内核内存不触发 AVB；但**重启即失效**，属于 runtime-only root。
4. **持久化**：解锁 BL 是唯一持久化路径。BL 锁着 → 改 `boot` 分区写 Magisk 补丁镜像这条路走不通（fastbootd 在 `unlocked:no` 下拒写，且 AVB 会判红）。

## 9. 现实结论

- 从 adb shell 到 root：**没有公开可用的利用**。内核 4.19.157 + SPL 2025-06 + 无 userns + 无 nf_tables，把已知路径全部封死。
- 唯一有实质希望的入口是 **kgsl**（世界可写、shell 可 open），但那需要自己挖，不是现成 PoC。
- 持久 root 的唯一正路是解锁 bootloader，而这条已在前一轮验证为固件层封死（`adb reboot bootloader` 与 `bootonce-bootloader` 均被 ABL 忽略，物理按键无 fastboot 映射）。

## 10. 崩溃取证（挖洞必备）

| 目标 | 命令 | 本机状态 |
|---|---|---|
| 内核日志 | `adb shell dmesg` | ❌ `klogctl: Permission denied`（`dmesg_restrict`） |
| 崩溃转储 | `adb shell ls /sys/fs/pstore` | ❌ `Permission denied` |
| tombstone | `adb shell ls /data/tombstones` | 需 root，shell 通常可读目录？未测 |
| 串口 | `/dev/ttyMSM0` | 需硬件 |
| ramoops | `ramdump_memshare_DIAG` 节点存在（`vendor_ramdump_device`） | 需 diag 权限 |

挖洞阶段没有 dmesg 会非常难受，实际做法是靠**受控崩溃 + 重启后 OTA 日志 / bugreport**，或者先拿一个能读 `dmesg` 的中间原语。

---

## 11. 实测：KGSL 从 adb shell 完整可驱动（已跑通）

环境里没有交叉工具链，NDK 下载被网络卡死（~0.03 MB/s），因此改用**纯 Python 手搓 ARM64 ELF**（`mkelf.py` / `mkelf_full.py`，产物 244–284 字节，零依赖、不链接 libc，直接走 `openat` / `ioctl` / `write` / `exit` 系统调用）。

### 11.1 对照实验

| 请求号 | 含义 | 退出码 | errno | 结论 |
|---|---|---|---|---|
| `0xDEADBEEF` | type 字节 = `0xBE` ≠ `0x09` | 231 | `ENOTTY`(25) | type 检查直接拒 |
| `0xC0180901` | type 对、nr=1 未注册 | 231 | `ENOTTY`(25) | **查表在拷贝之前** |
| `0xC0180902` | `KGSL_DEVICE_GETPROPERTY` | 242 | `EFAULT`(14) | 表项存在 → 进入 `copy_from_user` |

因为 `0xC0180901` 返回 `ENOTTY` 而不是 `EFAULT`，可以判定 KGSL 的 `ioctl` 分发顺序是「**先查表，后拷贝参数**」。于是 **`EFAULT` 就等价于「命令存在且注册」**——这是个很有用的判定技巧。

### 11.2 返回的真实数据

`KGSL_DEVICE_GETPROPERTY(KGSL_PROP_DEVICE_INFO)`，ioctl 返回 0：

```
01 00 00 00  00 09 01 06  00 01 00 00  95 ff ff ff
00 00 00 00  00 00 00 00  00 00 00 00  7f 00 00 00
00 00 08 00  00 00 00 00
```

| 偏移 | 值 | 解释 |
|---|---|---|
| `+0` | `0x00000001` | `device_id` |
| `+4` | `0x06010900` | `chip_id` = **Adreno 619** |
| `+8` | `0x00000100` | `mmu_enabled` 非零 |
| `+12` | `0xFFFFFF95` | `gmem_gpubaseaddr`（KGSL 连续地址基址偏移） |
| `+32` | `0x0000000000080000` | 512 KB 量级 |

### 11.3 核心原语命令可达性

| 请求号 | 命令 | 结构体大小 | 结果 |
|---|---|---|---|
| `0xC0200934` | `KGSL_GPUMEM_ALLOC_ID` | 32 B | `EFAULT` → **可调用** |
| `0xC0280945` | `KGSL_GPUOBJ_ALLOC` | 40 B | `EFAULT` → **可调用** |
| `0xC040094A` | `KGSL_GPU_COMMAND` | 64 B | `EFAULT` → **可调用** |
| `0xC0180902` | `KGSL_DEVICE_GETPROPERTY` | 24 B | `rc=0` → **已成功执行** |

这三条正是 kgsl 历史漏洞（CVE-2020-11201、CVE-2021-1905/1940/1941、CVE-2022-22064）全部依赖的入口。既然从 `u:r:shell:s0` 都能打进去，那么**任何针对该驱动的漏洞在这台机器上都是 shell 可达的**，不存在 SELinux 门槛。

### 11.4 下一步该做的事

1. 把 `GPUMEM_ALLOC_ID` / `GPUOBJ_ALLOC` 用合法参数跑通，拿到 `id` 与 `gpuaddr`，验证 `mmap_offset` 可映射（堆原语起点）。
2. 对 `GPU_COMMAND` 做参数边界的定向审计：`cmdsize`、`numcmds`、`objlist_size`、`synclist_size` 与对应指针长度的关系，历史上所有 kgsl 越界都出在这里的整数校验缺口。
3. 用 `slab_merge=on`（本机已开）把目标对象与可控对象共池，构造堆喷。
4. 加一个 `pstore` / `ramoops` 之外的崩溃捕获手段——本机 `dmesg` 被 `dmesg_restrict` 关掉，挖洞时只能靠「受控崩溃 + 重启后读 last_kmsg / bugreport」。

### 11.5 堆原语全链实测（单进程）

第一次尝试分进程跑 `ALLOC` → `GET_INFO`，第二步返回 `EINVAL`(22)。原因是 kgsl 对象生命周期绑定 fd：进程退出、fd 关闭，对象即刻回收，`id` 在新进程里已失效。改为**同一进程同一 fd 内连续完成三段**后，结果如下（阶段标记直接写 stdout）：

```
$ /data/local/tmp/kgslchain
ABC            ← 输出字节 41 42 43
EXIT=243       ← errno 13 = EACCES
```

| 标记 | 阶段 | 结果 |
|---|---|---|
| `A` (0x41) | `open("/dev/kgsl-3d0", O_RDWR)` | ✅ 成功 |
| `B` (0x42) | `ioctl KGSL_GPUMEM_ALLOC_ID` 1 MB | ✅ 成功，返回 `id`、`gpuaddr` |
| `C` (0x43) | `ioctl KGSL_GPUMEM_GET_INFO` | ✅ 成功，返回 `size`、`mmap_offset` |
| `D` (0x44) | `mmap(NULL,size,RW,MAP_SHARED,fd,offset)` | ❌ **`EACCES`(13)** |

单步 `ALLOC` 的完整返回（独立进程，仅供参考数值）：

```
01 00 00 00 | 00 00 0c 00 | 00 00 10 00 00 00 00 00
00 00 10 00 00 00 00 00 | 00 00 00 00 05 00 00 00
```

| 字段 | 值 |
|---|---|
| `id` | `1` |
| `flags` | `0x000C0000` |
| `size` | `0x100000`（1 MB，与申请一致） |
| `mmapsize` | `0x100000` |
| `gpuaddr` | **`0x0000000500000000`**（KGSL 连续 GPU 地址空间） |

**结论：能在内核 GPU 池里分配对象、能取到 mmap_offset，但 `mmap` 被 `EACCES` 拒绝。** 这说明 `shell` 域对 `gpu_device` 的 `ioctl` 放行、`mmap` 权限单独收紧。

对利用的影响：
- 走 CPU 直接映射读写的思路（部分 kgsl PoC 的开局）在本机不通。
- 仍然可用的是 `GPU_COMMAND` 投递（GPU 侧读写）、`GPUOBJ_IMPORT` 建立映射关系、以及纯粹依赖 `ALLOC`/`FREE` 做堆布局（slab 合并已开，跨类型共池有利）。
- kgsl 历史上多数可用漏洞恰好依赖「分配 + GPU 命令投递」而非 CPU mmap，因此这个限制不等于把门关死。




