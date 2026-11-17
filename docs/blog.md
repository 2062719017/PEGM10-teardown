# 我把一台 OPPO Reno5 K 从头翻到尾：一次没成功的提权，和一个骗了我半天的 `movz`

> 一台 ColorOS 13 的国行 Reno5 K，目标是拿到 root。折腾了一整天，结论是没拿到。
> 但过程中踩的坑、拆的协议、写错的一个 ARM64 立即数，可能比"成功"更有意思。

---

## 起因

手上有台闲置的 OPPO Reno5 K 5G（`PEGM10` / `OP4E59`），国行 ColorOS 13.1.0，Android 13。数据早就清空了，正好拿来当实验田。

目标很朴素：**解锁 bootloader，拿 root。**

一开始的想法也很朴素——进 fastboot，`fastboot flashing unlock`，完事。

事实证明，这个朴素的想法在第一步就撞墙了。

**环境**：Windows 11 + PowerShell，`adb`/`fastboot` 来自 platform-tools 37.0.0。
没有交叉编译器（后面会说为什么），反汇编用 capstone，USB 用 libusb。

---

## 第一层：摸底，然后发现这机器没戏

先把能读的属性全读一遍：

```
ro.product.manufacturer  = OPPO
ro.product.model         = PEGM10
ro.build.version.release = 13
ro.build.display.id      = PEGM10_13.1.0.2101(CN01)
ro.boot.flash.locked     = 1
ro.boot.verifiedbootstate= green
sys.oem_unlock_allowed   = 1     ← 开发者选项里 OEM 解锁是开的
```

`sys.oem_unlock_allowed=1` 一度让人有希望。后来才知道，那只是个 UI 开关，跟 bootloader 放不放行完全是两回事。

真正致命的是内核配置。`/proc/config.gz` 居然是可读的，6343 行，逐条看下来：

| 配置项 | 值 | 意味着什么 |
|---|---|---|
| `CONFIG_USER_NS` | **未设置** | `unshare -U` 直接 `EINVAL`，所有依赖非特权 user namespace 的利用全废 |
| `CONFIG_NF_TABLES` | **未编译** | nf_tables 整族 CVE 连攻击面都不存在 |
| `CONFIG_VSOCKETS` | 未设置 | vsock 系 UAF 无入口 |
| `CONFIG_STATIC_USERMODEHELPER` | `y`，`PATH=""` | `modprobe_path` 覆盖后不会执行任何程序 |
| `CONFIG_SLAB_FREELIST_HARDENED` | `y` | 堆喷门槛拉高 |
| `CONFIG_HARDENED_USERCOPY` | `y`（含 PAGESPAN） | 跨堆/跨栈拷贝被拦 |
| io_uring | 4.19 分支压根没有 | io_uring 系全灭 |

内核版本 `4.19.157-perf+`，编译于 **2025-06-12**，安全补丁 `2025-06-01`。

翻译一下：**2024 年及以前所有公开的 Android 内核提权 PoC，在这台机器上全部失效。** 不是"难打"，是"没得打"。

---

## 第二层：Bootloader 里根本没有 fastboot

按音量键进 fastboot，怎么按都进不去。

一开始以为是按键组合不对。查了 ColorOS 的组合键：

| 组合 | 实际进入 |
|---|---|
| 音量下 + 电源 | ColorOS Recovery |
| 音量上 + 电源 | 强制重启 |
| 音量上 + 音量下 + 电源 | Recovery |

没有一个是 fastboot。

然后试了命令行：

```
adb reboot bootloader
```

设备重启了。USB 上短暂出现一个 `18D1:4EE8`，Windows 把它识别成"MIDI function"。二十多秒后它变回 `22D9:2765`——系统起来了。

看 bootreason：

```
ro.boot.bootreason = bootloader
sys.boot.reason    = bootloader
ro.boot.mode       = reboot
```

**ABL 收到并记录了 "bootloader" 指令，然后它选择冷启动系统。**

换句话说：请求送到了，但没有任何代码去处理它。那个 `18D1:4EE8` 只是启动过程里的过渡态，跟 fastboot 一点关系都没有。

后来在固件包里拿到 `abl.elf`，只有 225KB。真正的 ABL（基于 edk2）动辄 1-2MB。搜索整块二进制，`fastboot`、`bootloader`、`unlock`、`volume_down` 这些字符串**一个都没有**。

不过这里有个反转——`abl.elf` 的代码段熵值是 **7.884 bits/byte**，开头 16 字节全 0，之后是高熵数据。**代码是加密的。**

所以"搜不到 fastboot 字符串"并不能证明它不存在，代码根本不在明文里。真正站得住的只有行为证据：指令发了，系统起来了。

另外 `fastboot` 也不是全无收获——`adb reboot fastboot` 能进 **fastbootd**：

```
fastboot getvar is-userspace   → yes
fastboot getvar unlocked       → no
fastboot getvar secure         → yes
fastboot getvar slot-count     → 0
```

fastbootd 能管 super 里的动态分区，但解锁相关的命令一个都不认：

```
fastboot flashing get_unlock_ability  → Unrecognized command
fastboot oem device-info              → Unable to open fastboot HAL
```

它是跑在 Android 用户空间里的服务，管不到 bootloader 的锁。两条路都断了。

---

## 第三层：kgsl，最接近成功的一条

公开 CVE 全废之后，得自己找。手上权限最宽的内核设备节点是 `/dev/kgsl-3d0`：

```
crw-rw-rw- 1 system system u:object_r:gpu_device:s0 509, 0 /dev/kgsl-3d0
```

世界可写，而且从 `u:r:shell:s0` 能直接 `open()`。Adreno 619。

### 先解决了"怎么跑代码"的问题

麻烦的是环境里没有交叉编译器。NDK 下载速度 ~0.03 MB/s，国内镜像 0.02 MB/s，都是几小时起步，不现实。

于是换了个思路：**用 Python 手搓 ARM64 机器码，直接生成 ELF。**

284 字节的二进制，不链接 libc，直接发系统调用：

```python
def movz64(rd, imm16, shift=0):
    return 0xD2800000 | ((shift // 16) << 21) | ((imm16 & 0xFFFF) << 5) | rd
```

`openat` + `ioctl` + `exit`，退出码用 `256 - x` 映射成 errno。`adb push` 过去 `chmod 755` 就能跑。

### 用 errno 反推内核行为

判断 SELinux 有没有拦 ioctl，靠的是错误码差异：

| 请求号 | 含义 | errno | 结论 |
|---|---|---|---|
| `0xDEADBEEF` | type 字节不对 | `ENOTTY`(25) | type 检查直接拒 |
| `0xC0180901` | type 对、nr 未注册 | `ENOTTY`(25) | **查表发生在拷参之前** |
| `0xC0180902` | `KGSL_DEVICE_GETPROPERTY` | `EFAULT`(14) | 表项存在 → 进入 `copy_from_user` |

`0xC0180901` 返回的是 `ENOTTY` 而不是 `EFAULT`，这一条特别值钱：它证明 KGSL 的分发顺序是"**先查表，后拷贝参数**"。于是 **`EFAULT` 就等价于"命令存在且注册"**，可以拿它当探针。

如果是 SELinux 拦的，会看到 `EPERM` 或 `EACCES`。没出现。**shell 域对 `gpu_device` 的 ioctl 是放行的。**

### 把整张 ioctl 表枚举出来

写了个循环遍历 `nr = 0x01..0x5F`，每个 nr 写 2 字节记录（nr + 返回值低字节）回传。295 字节的二进制跑完，190 字节数据，95 条记录。

结果里最值钱的几条：

| 状态 | nr |
|---|---|
| 零参数即成功 | `0x38` `0x39` `0x3A` `0x40` `0x41` `0x45` `0x58` `0x5C` |
| **`EFAULT`（解引用 struct 内指针）** | `0x49` `0x5B` |
| `ENOMEM`（走到分配层） | `0x48` `0x50`–`0x55` |
| `EPERM`（权限拒绝） | `0x3B` |

然后真的把 GPU 内存分配出来了：

```
KGSL_GPUMEM_ALLOC_ID 1MB →
  id        = 1
  flags     = 0x000C0000
  size      = 0x100000
  mmapsize  = 0x100000
  gpuaddr   = 0x0000000500000000
```

`0x500000000` 是 KGSL 的连续 GPU 地址空间基址段。

### 然后卡在 mmap

单进程跑完整链路（`open → ALLOC → GET_INFO → mmap`），加了阶段标记输出：

```
$ /data/local/tmp/kgslchain
ABC                 # A=open B=alloc C=get_info 全通过
exit=243            # 256-243 = 13 = EACCES，卡在 mmap
```

这条链的 mmap 长度是从 `GET_INFO` 读回来的真实值（`0x100000`），不是硬编码。所以 **`EACCES` 是可信的**——SELinux 对 `gpu_device` 允许 `ioctl`，但拒绝 `mmap`。

### context 建不出来

`GPU_COMMAND` 需要 `context_id`，得先 `DRAWCTXT_CREATE`。这个命令一直返回 `EINVAL`。

穷举了 `flags = type << 20`，type 从 0 到 31（覆盖 `KGSL_CONTEXT_TYPE_MASK` 全部取值），加上 6 种结构体尺寸、4 组 flags 组合：

```
type = 0..31  →  全部 errno=22 (EINVAL)
```

32 种类型，无一例外。不是参数没配对，是这条路径被整体拒绝。

剩下 `0x49` 和 `0x5B` 两个口子。喂真实指针后：

| nr | 指针=NULL | 指针=有效地址 | 含义 |
|---|---|---|---|
| `0x49` | `EFAULT` | `EINVAL` | 指针解引用成功，进参数校验 |
| `0x5B` | `EFAULT` | **`EAGAIN`** | 读取类接口，当前无数据 |

`EAGAIN` 挺有意思——"稍后重试"语义，说明数据就绪时它真的会返回东西。但结构体布局未知，逆向成本很高。

kgsl 这条路，到这里算是走到能走的最远处了。

---

## 第四层：binder，一个至今没解开的谜

`/dev/binder` 和 `/dev/hwbinder` 都能从 shell 直接 open。协议版本 8，完整实现。

几个基础 ioctl 全部正常：

| 命令 | 结果 |
|---|---|
| `BINDER_VERSION` | rc=0，版本 **8** |
| `BINDER_SET_MAX_THREADS` | rc=0 |
| `BINDER_WRITE_READ`（空结构） | rc=0 |
| **`BINDER_SET_CONTEXT_MGR`** | **`EBUSY`(16)** |

`EBUSY` 这条特别关键：它是"已经有 context manager 了"的业务错误，不是拒绝。**说明写类 ioctl 完全能抵达驱动内部并执行。**

那问题就在 `binder_thread_write` 处理 `BC_*` 命令那一层。

发一条最无害的 `BC_ENTER_LOOPER`（0x0c，无参数，只是置一个 looper 标志位）：

```
binder_write_read:
  +0  : 04 00 00 00 00 00 00 00     write_size   = 4
  +16 : 60 2e db d4 7f 00 00 00     write_buffer = 有效栈地址
写缓冲: 0c 00 00 00                   BC_ENTER_LOOPER

结果: errno=22 (EINVAL), write_consumed=0
```

结构体完全正确，内核返回 `EINVAL`，**一个字节都没消费**。

排除掉的假设：

| 假设 | 实验 | 结果 |
|---|---|---|
| mmap 未建立 | 先 mmap 再写 | ❌ 仍 EINVAL |
| mmap 尺寸不足 | 4K / 128K / 1M / 1M-8K | ❌ 与尺寸无关 |
| prot 错误 | `PROT_READ` / `READ+WRITE` | ❌ 无关 |
| `cmd` 常量算错 | 同值空 BWR 返回 0 | ❌ 常量正确 |
| 结构体尺寸不符 | 扫 size 8..127 | ❌ 48 已被空调用证明正确 |
| `write_size` 语义歧义 | 4 / 8 / 16 三种 | ❌ 全部 EINVAL |
| 缺 `read_size` | 同时设置 read_size + read_buffer | ❌ 仍 EINVAL |
| 缺初始化序列 | 补 `BINDER_VERSION` + `SET_MAX_THREADS` | ❌ 仍 EINVAL |
| 命令字不被识别 | 扫 0x00/0x0b/0x0c/0x0d | ❌ 全部 EINVAL |
| **栈页不可读** | **改用 mmap 匿名页作写缓冲** | ❌ 仍 EINVAL |
| SELinux 域不同 | `ps -Z` 对比 | ❌ 域都正常 |

`EINVAL` + `consumed=0` 在语义上精确对应 `binder_thread_write` 的 `default:` 分支（未知命令），但 `0x0c` 就是 `BC_ENTER_LOOPER`。逻辑上是矛盾的。

关键对照：

| 主体 | 结果 |
|---|---|
| `service call activity 1`（libbinder） | ✅ 返回完整 Parcel |
| 我们的裸 ELF ioctl | ❌ EINVAL，consumed=0 |

**libbinder 能发事务，裸 ioctl 不能。**

这个谜到今天也没解开。要搞清楚得反编译这台机器的 binder 驱动，或者从 `last_kmsg` 里找 `pr_err("%d:%d unknown command %d")` 的内核打印。

---

## 转折：拿到官方固件包

卡住的时候，翻到一个同版本的官方固件包：`PEGM10domestic_11_13.1.0.2101CN01_2025061222420157`。

`version_info.txt` 里写着：

```json
{
  "compile_time": "2025-06-12 20:40:35",
  "platform": "SM7225",
  "version_name": "PEGM10_13.1.0.2101(CN01)_250612"
}
```

和手机上跑的内核编译时间**完全吻合**。里面的东西：

| 文件 | 大小 | 用途 |
|---|---|---|
| `boot.img` | 100 MB | 内核镜像 |
| `abl.elf` | 225 KB | Bootloader |
| `prog_firehose_ddr.elf` | 777 KB | **EDL 用的签名 programmer** |
| `vendor.img` | 404 MB | 完整 vendor |
| `rawprogram*.xml` | — | 分区表 |

### 把内核挖出来

```python
kernel_size = 42625040      # boot.img v2 头偏移 8
page_size   = 4096
header_version = 2
```

从偏移 4096 提取 42 MB，开头 `00 00 82 14` 是 ARM64 的 `b` 指令——未压缩的 Image。

cmdline 里有个对漏洞利用有利的发现：

```
kpti=off
```

内核页表隔离关闭了。

### 反汇编环境

MinGW 自带的 `objdump` 查了一下支持列表：

```
supported targets: pe-x86-64 elf64-x86-64 ... 
```

只有 x86，没有 aarch64。

转而装 capstone：

```bash
pip install capstone -i https://pypi.tuna.tsinghua.edu.cn/simple
```

1.3 MB，**5 MB/s**，秒装。ARM64 反汇编立刻可用。

内核基址通过 ADRP+ADD 交叉引用验证出来：

```
文件偏移 0  ==  虚拟地址 0xffff000008008000
```

验证方法：在 `.rodata` 里找一条已知的格式串，扫描全镜像找能算出该地址的 `ADRP + ADD` 指令对，然后反汇编那段代码，看语义是否自洽。反出来的第一条是标准函数序言：

```
0xffff000008eebd80  stp  x29, x30, [sp, #-0x60]!
0xffff000008eebe08  bl   #0xffff00000828faf0        ← printk
```

### 分区表

注意 **sector size 是 4096**，不是常规的 512：

| 分区 | LUN | 起始 sector | 起始字节 | 大小 |
|---|---|---|---|---|
| `abl` | 4 | 60678 | `0xed06000` | 1024 KB |
| `vbmeta` | 4 | 102362 | `0x18fda000` | 64 KB |
| `oplus_sec` | 4 | 189962 | `0x2e60a000` | 10240 KB |
| **`devinfo`** | **4** | **192522** | **`0x2f00a000`** | **4 KB** |

`devinfo` 只有 4096 字节（1 个 sector）。标准 Qualcomm 的 `devinfo` 就是 1 页，前 4 字节通常是 `is_unlocked`。

而固件包里 `devinfo` 的 `filename=""`——**官方刷机流程不写它**。反过来意味着可以手动写。

另一个意外发现：`oplus_sec.mbn` 是 **32 位 ARM ELF**（`e_machine=0x28=EM_ARM`），不是数据块。反汇编看字符串：

```
OPLUS ROOT CA 1
OPLUS Attestation CA
qsee_stor_write_sectors
qsee_fts_read_file
hal_core_secure_info_verify_sign
```

**它是跑在 QSEE 里的 TEE 密码学引擎应用，跟 bootloader 解锁没关系。** 之前猜它是"解锁校验数据"，猜错了。

---

## 第五层：EDL，从驱动签名一路踩到 Sahara

有了签名的 programmer，EDL 就成了最现实的路——它能绕过一切，直接读写任意分区。

### 驱动：x64 Windows 拒绝未签名 INF

先确认 EDL 能进：

```
adb reboot edl
→ USB 出现 VID_05C6&PID_9008
→ QUSB_BULK_CID:041B_SN:1EA0E2D9
```

但驱动状态是 `CM_PROB_FAILED_INSTALL`，libusb 根本看不见设备。

于是开始了一连串尝试：

| 尝试 | 结果 |
|---|---|
| 自写 INF + `pnputil`（带 CatalogFile） | ❌ "INF 不含数字签名信息" |
| 自写 INF（无 CatalogFile） | ❌ 同上 |
| Windows Update 驱动搜索 | ❌ `0x80248014` |
| `DiInstallDevice` + `INSTALLFLAG_FORCE` 强制绑 `winusb.inf` | ⚠️ 状态变 OK 但**没有 Service 项**，libusb 仍看不见 |
| `SetupDiSetDeviceInstallParams` 限定 DriverPath | ❌ 枚举不到驱动（硬件 ID 不匹配） |
| 用已签名的 `android_winusb.inf` 强绑 | ❌ 只有 VID_18D1 条目 |
| 从 Zadig 提取内嵌驱动 | ❌ Zadig 是 **UPX 压缩**的，资源里没有驱动 |

根本原因：微软 inbox 的 `winusb.inf` 只匹配 `USB\MS_COMP_WINUSB` 和 `Class_ff&SubClass_42&Prot_01`（ADB），而 EDL 设备是 `Class_FF&SubClass_FF&Prot_10`，没有现成的签名 INF 能匹配。

最后靠 **Zadig** 解决。libwdi 会现场生成针对具体 VID/PID 的 INF，配上它自带的微软交叉签名 `.cat`：

```
Signer Name: USB\VID_05C6&PID_9008 (libwdi autogenerated)
Service:     WinUSB
```

### pyusb 在 Windows/WinUSB 下的坑

设备能 open 了，但接下来撞到一个很不友好的 bug：

```python
d.get_active_configuration()
# NotImplementedError: Operation not supported or unimplemented on this platform

d._ctx.managed_open()
# NotImplementedError: 同上
```

pyusb 1.3.1 + libusb-package，在 Windows 的 WinUSB 后端下，这两条路都要读 configuration descriptor，而后端没实现。

拿不到 device_handle，`dev.read(0x81, ...)` 会直接：

```
KeyError: 129
```

**解决办法：完全绕开 pyusb，用 ctypes 直接调 libusb。**

```python
lib = ctypes.CDLL(libusb_package.find_library('libusb-1.0'))
lib.libusb_bulk_transfer.argtypes = [
    ctypes.c_void_p, ctypes.c_ubyte, ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_int, ctypes.POINTER(ctypes.c_int), ctypes.c_uint]
```

`libusb_init` → `libusb_open_device_with_vid_pid` → `libusb_claim_interface` → `libusb_bulk_transfer`，一路走原生 API。

顺带一个细节：`libusb_package.find_library()` **必须传 candidate 参数**，不传会 `TypeError`。之前把它当 pyusb backend 的回调传进去时是无参调用的，所以没发现。

### Sahara：设备根本不收数据

原生 ctypes 通了之后，Sahara 握手成功：

```
[+] HELLO version=2 min=1 max_packet=1024 mode=0
[+] 已回 HELLO_RESP
[+] END_OF_IMAGE image=13 status=1        ← 立刻失败
```

标准 Sahara 流程应该是：

```
HELLO → HELLO_RESP → READ_DATA(多次) → END_OF_IMAGE(status=0) → DONE → DONE_RESP
```

本机**完全跳过了所有 READ_DATA**，收到 `HELLO_RESP` 就直接 `END_OF_IMAGE(image_id=13, status=1)`。

`image_id=13` 是 SBL，`status=1` 是 `SAHARA_STATUS_FAILURE`。

试过的东西：

| 尝试 | 结果 |
|---|---|
| HELLO_RESP 按设备发来的原值回 | ❌ 仍失败 |
| `DONE` 用 `len=8` | ❌ 设备继续发 `END_OF_IMAGE` |
| `DONE` 用 `len=12`（带 image_id/status） | ❌ 同上 |
| 主机主动先发 `HELLO` | ❌ 设备仍回 `END_OF_IMAGE(13,1)` |
| 先发 `SAHARA_RESET` | ⚠️ 收到 `RESET_RESP` 但设备不再重发 HELLO |

**设备一个字节的数据都不要。**

第一次 `END_OF_IMAGE` 的 `status` 读到过 **1024**，恰好等于我们 `HELLO_RESP` 里 `max_packet_size` 的值（偏移 16 处 `00 04 00 00`）。这个巧合暗示可能存在字节对齐问题，但后续会话里 `status` 稳定为 1，没能复现。

---

## 踩过的坑，这部分可能最有用

### 1. `movz` 立即数截断——一个 bug 伪造了三条"内核拒绝"的结论

手搓 ARM64 时写了个辅助函数：

```python
def movz64(rd, imm16, shift=0):
    return 0xD2800000 | ((shift // 16) << 21) | ((imm16 & 0xFFFF) << 5) | rd
```

看起来没问题。但 **`movz` 只能装载 16 位立即数**，`& 0xFFFF` 会把高位直接截掉。

于是 `movz64(1, 131072)`（0x20000）实际生成的是 `movz x1, #0`。

结果：binder 的 mmap 测试里，`128K`、`1M` 全部"失败"——**因为实际传的 `length` 是 0**。当时得出的结论是"内核只允许 4096 一页的映射"，写进了报告，还挺得意。

修正成 `movz + movk` 链之后重测：

| mmap 尺寸 | 修正前 | 修正后 |
|---|---|---|
| 4096 | ✅ | ✅ |
| 131072 | ❌ | ✅ |
| 1040384（libbinder 标准） | ❌ | ✅ |
| 1048576 | ❌ | ✅ |

**binder 的 mmap 从来没被拒绝过。** 之前那整段分析是建立在假数据上的。

教训：**手搓机器码时，任何大于 16 位的立即数都要用 `movz+movk` 链，而且要真的反汇编验证生成的指令。** 后来加了个 `load_const()` 统一处理，也养成了 dump 指令列表逐个核对的习惯。

### 2. `drain()` 会吃掉 Sahara HELLO

为了清掉 USB 缓冲里的"残留数据"，写了个 `drain()`。

问题是 **Sahara 的 HELLO 包正好 48 字节**，跟"残留"没法区分。连接设备后第一件事就 drain，HELLO 直接被当成垃圾扔掉。

后续所有解析全部错位——`status` 读出 1024 这种鬼值就是这么来的。

教训：**协议握手的第一包不能"清理"，要先按协议解析。**

### 3. 反复折腾会把 EDL 逼进死状态，只能物理断电

在 Sahara 上反复试不同方案，设备进了 `CM_PROB_FAILED_START`，然后变成"未知 USB 设备（设备描述符请求失败）"：

```
InstanceId : USB\VID_0000&PID_0002\6&15E088B1&0&2
```

重启 USB hub、`pnputil /disable-device` + `/enable-device`、`restart-device`——全都救不回来。

最后是**长按电源 15 秒**（或者音量上+电源）强制断电，才恢复正常。

中间还遇到过一次"按电源完全没反应"，怀疑是 EDL 待机两小时把电池耗光了，充了半小时才活过来。

教训：**EDL 的 Sahara 状态机很脆，不要在一个会话里反复试命令。每次失败宁可物理重启一次，重新来。**

### 4. `oplus_sec` 不是解锁校验数据

一开始从分区名猜它是"OPPO 的安全校验分区"，于是花了很多精力琢磨怎么骗过它。

反汇编一看，是跑在 QSEE 里的 TEE 密码学应用（`cryptoeng`），管签名验签，跟 bootloader 解锁毫无关系。

教训：**别按分区名猜功能，直接反汇编。**

---

## 最后的结论

这台机器在**每一个层面**都是关着的：

| 层面 | 状态 |
|---|---|
| 公开内核 CVE | SPL 2025-06 全修 |
| Bootloader fastboot | 无实现（abl 加密，行为证据确凿） |
| kgsl GPU 驱动 | mmap `EACCES`、context 全 `EINVAL` |
| binder | `BC_*` 命令被厂商拦截（11 个假设排除） |
| OPPO 厂商节点 | SELinux 全拒（`proc_oppo_secure_common_file` 等标签） |
| EDL 刷写 | PBL 层拒绝 Sahara 上传 |

和这些防护对得上号的东西：`abl.elf` 加密、`oplus_sec` 是 TEE 应用、系统里有个服务叫 `anti_root_dialog`（反 root 提示）。

**这不是哪个环节没找对参数，是整套设计好的封锁。** 这台型号在出厂时就没打算让用户动底层。

---

## 但过程中攒下的东西是真的

| 产出 | 说明 |
|---|---|
| **内核镜像 + 反汇编环境** | 42 MB `kernel.bin`，基址 `0xffff000008008000`，capstone + ADRP 交叉引用定位函数的技术验证通过 |
| **KGSL ioctl 全表** | 95 个 nr 的完整地图，哪些通、哪些死、哪些是活口 |
| **物理分区表** | LUN / sector / 字节偏移，`devinfo` 精确定位到 LUN4 / sector 192522 |
| **`rawlibusb.py`** | 纯 ctypes 的 libusb 封装，绕开 pyusb 在 Windows/WinUSB 下的 `NotImplementedError` |
| **EDL 客户端** | Sahara + Firehose 完整实现（虽然在这台机器上没用上） |

`rawlibusb.py` 大概是这次最通用的东西。pyusb 在 Windows/WinUSB 下的那个 `get_configuration_descriptor` 坑，网上资料很少，啃出来之后任何高通设备的 EDL 操作都能直接用。

---

## 几句实在话

**没拿到 root。** 这台机器目前的防护水平，靠现成方法是不行的。

中间也确实走了弯路——那个 `movz` 的 bug 让我在错误的方向上浪费了不少时间，还一度得出了"内核只允许一页 mmap"这种完全错误的结论。写下来是想提醒自己：**手搓底层代码时，验证生成的指令比相信辅助函数更重要。**

不过整件事里最有意思的地方，反而不是"怎么攻破"，而是**用 errno 反推内核行为**这件事。`ENOTTY` 和 `EFAULT` 的差异就能证明"分发顺序是先查表后拷参"，进而把 `EFAULT` 变成一个"命令存在"的探针——这种用错误码差异做黑盒探测的思路，比任何一个具体的 CVE 都更耐得住版本变化。

如果下次再碰这台机器，会从两个方向入手：

1. **反汇编本机的 binder 驱动**，搞清楚 `binder_thread_write` 到底为什么拒绝 `BC_*` 命令
2. **把 `0x5B` 那个返回 `EAGAIN` 的 kgsl 接口啃下来**——它是目前唯一表现出正常语义的未探索接口

至于现在——手机好好地在用，什么都没丢，什么都没坏。

---

*本文所有操作均在本人自有、数据已清空的设备上进行。*
