# PEGM10 Teardown

> OPPO Reno5 K 5G（`PEGM10` / `OP4E59`）提权尝试的完整记录。
>
> **结论先行：没成功。** 这台机器在出厂设计上就把底层封死了。
> 但这个仓库里有**可复用的工具**和**一份详细的踩坑清单**，也许能帮你少走两天弯路。

---

## 这台机器为什么打不动

设备信息：

| 项 | 值 |
|---|---|
| 型号 | OPPO Reno5 K 5G（`PEGM10` / `OP4E59`） |
| 系统 | ColorOS `V13.1.0` / Android 13（SDK 33）/ `user` build / 国行 `CN01` |
| 内核 | `4.19.157-perf+`，编译于 **2025-06-12**，clang 10.0.7 |
| 安全补丁 | **2025-06-01** |
| 平台 | Qualcomm lito（SM7225 / 骁龙 750G），Adreno 619，aarch64 |

六个方向全部撞墙：

| 层面 | 状态 | 关键证据 |
|---|---|---|
| 公开内核 CVE | ❌ 全废 | SPL 2025-06 + 内核 2025-06 编译 |
| Bootloader fastboot | ❌ 无实现 | `bootreason=bootloader` 被记录，系统照常启动 |
| kgsl（GPU 驱动） | 🟡 部分可达 | 能分配、能 ioctl；`mmap` 返回 `EACCES`，`DRAWCTXT_CREATE` 全 `EINVAL` |
| binder | 🟡 部分可达 | 协议正常；裸 ioctl 发 `BC_*` 一律 `EINVAL` 且 `consumed=0` |
| OPPO 厂商节点 | ❌ 全拒 | `/proc/oplus_*` 被 SELinux 拦死 |
| EDL 刷写 | ❌ 拒绝 | 收到 `HELLO_RESP` 后直接 `END_OF_IMAGE(status=1)`，不发一个字节 `READ_DATA` |

和这些封锁对得上号的防护措施：`abl.elf` 代码段加密（熵 7.884 bits/byte）、`oplus_sec` 是跑在 QSEE 里的 TEE 密码学应用、系统里有个叫 `anti_root_dialog` 的服务。

**这不是哪个参数没找对，是整套设计好的封锁。**

---

## 内核配置：为什么公开 PoC 全废

`/proc/config.gz` 在这台机器上是**可读的**（6343 行）。逐条看完就知道没戏：

| 配置项 | 值 | 影响 |
|---|---|---|
| `CONFIG_USER_NS` | **未设置** | `unshare -U` → `EINVAL`，所有依赖非特权 userns 的利用全废 |
| `CONFIG_NF_TABLES` | **未编译** | nf_tables 整族 CVE 连攻击面都不存在 |
| `CONFIG_VSOCKETS` | 未设置 | vsock 系 UAF 无入口 |
| `CONFIG_STATIC_USERMODEHELPER` | `y`，`PATH=""` | `modprobe_path` 覆盖后不执行任何程序 |
| `CONFIG_SLAB_FREELIST_HARDENED` | `y` | 堆喷门槛拉高 |
| `CONFIG_HARDENED_USERCOPY` | `y`（含 PAGESPAN） | 跨堆/跨栈拷贝被拦 |
| `CONFIG_KASAN` | 未开 | 崩溃即 oops，无检测兜底 |
| io_uring | 4.19 分支压根没有 | io_uring 系全灭 |
| shell 进程 seccomp | `0` | 系统调用不受限（这个反而是好事） |

顺带一个对利用有利的发现：`boot.img` 的 cmdline 里有 **`kpti=off`**——内核页表隔离关闭。

---

## 仓库结构

```
docs/            完整调查记录（建议按编号顺序读）
  README.md      阅读索引
  00-overview.md          总报告：六个方向的完整结论与证据链
  01-hardening.md         环境摸底：内核配置逐项 + 为什么公开 CVE 全废
  02-kgsl.md              kgsl 攻击面：95 个 ioctl 编号的完整地图
  03-binder.md            binder 探测：BC 命令被拒的 11 个假设与排除
  04-firmware-edl.md      固件包分析 + EDL 实机验证完整记录
  blog.md                 面向发布的长文（约 5400 字）

pitfalls/        ★ 踩坑清单——如果你只看一个目录，看这个
  README.md

tools/
  arm64/         ★ 零编译器手搓 ARM64 ELF 的工具链
  edl/           ★ 纯 ctypes 的 libusb 封装 + Sahara/Firehose 客户端
  analysis/      内核镜像符号定位、ELF/MBN 解析
  drivers/       Windows 驱动绑定的尝试记录（全是失败方案）
  crashlog.ps1   Android 崩溃日志抓取
  probe.c        NDK 版内核攻击面探针（有编译器时用这个）

notes/
  partitions.md  物理分区表（LUN / sector / 字节偏移）
  device-notes.md  设备零散属性与观察
```

---

## 最有价值的三个东西

### 1. `tools/edl/rawlibusb.py` — 绕开 pyusb 在 Windows 的坑

pyusb 1.3.1 + libusb-package 在 **Windows / WinUSB 后端**下会在两处直接抛异常：

```python
d.get_active_configuration()
# NotImplementedError: Operation not supported or unimplemented on this platform

d._ctx.managed_open()
# NotImplementedError: 同上
```

这两条路都要读 configuration descriptor，而后端没实现。结果就是拿不到 `device_handle`，
`dev.read(0x81, ...)` 会直接 `KeyError: 129`。

`rawlibusb.py` 用 ctypes 直接调原生 API，完全绕开 pyusb 的描述符层：

```python
libusb_init → libusb_open_device_with_vid_pid → libusb_claim_interface → libusb_bulk_transfer
```

这个坑网上资料很少，**任何 Qualcomm 设备的 EDL 操作都能直接复用**。

### 2. `tools/arm64/` — 没有交叉编译器也能出 ARM64 二进制

环境里没有 NDK（下载速率 0.03 MB/s，不现实），所以整套探针是**用 Python 手搓机器码 + 手工构造 ELF** 生成的。
产物 244–600 字节，不链接 libc，直接发系统调用。

`mkelf_call.py` 是通用调用器，一行命令就能测任意 ioctl：

```bash
python mkelf_call.py probe 0xC0200934 32 "8:0x100000:8"
#                      输出名  请求号     结构体大小  字段表(偏移:值:宽度)
```

`mkelf_scan.py` 能枚举整张 ioctl 表（循环 nr 1..0x5F，每个写 2 字节记录回传）。

### 3. `pitfalls/README.md` — 猫踩过的坑都在里面

包括那个**骗了我半天的 `movz` 立即数截断 bug**，它伪造了三条"内核拒绝"的假结论。

---

## 复现环境

| 组件 | 说明 |
|---|---|
| `adb` / `fastboot` | platform-tools 37.0.0+ |
| Python | 3.10+ |
| `pyusb` + `libusb-package` | `pip install pyusb libusb-package` |
| `capstone` | `pip install capstone`（反汇编用） |
| Windows 上跑 EDL | 需要把 `05C6:9008` 绑到 WinUSB，用 [Zadig](https://zadig.akeo.ie/) |

国内装 Python 包建议加镜像：

```bash
pip install capstone -i https://pypi.tuna.tsinghua.edu.cn/simple
```

---

## 如果你手上有同型号机器

**先说结论：按这个仓库里的方法拿 root，大概率是拿不到的。** 封锁在固件层，不在系统层。

不过有些东西值得先确认，免得白花时间：

```bash
# 1. 补丁级别够不够新
adb shell getprop ro.build.version.security_patch

# 2. 内核配置（可读的话直接看）
adb shell "zcat /proc/config.gz | grep -E 'USER_NS|NF_TABLES|VSOCKETS|STATIC_USERMODEHELPER'"

# 3. bootloader 是否真的没 fastboot
adb reboot bootloader && adb shell getprop ro.boot.bootreason   # 能回来就是没进
```

如果 `CONFIG_USER_NS` 是打开的、SPL 比较旧，那还有的打。反过来的话，建议直接换机器。

**能考虑的方向**（按可行性）：

1. 等厂商开放解锁（Reno 系列国行基本没戏，深度测试只覆盖一加部分机型）
2. 换一台一加数字系列或国际版 OPPO
3. 自己从 kgsl / binder 挖新漏洞（周期以月计，且不保证）

---

## 未解之谜

留两个猫没搞明白的问题，也许有人能接上：

1. **binder 的 `BC_*` 命令为什么被拒。**
   `BINDER_SET_CONTEXT_MGR` 能返回业务语义的 `EBUSY`，证明写类 ioctl 能抵达驱动内部；
   但 `binder_thread_write` 层的 `BC_ENTER_LOOPER`（无参数、只置一个标志位）却返回 `EINVAL` 且 `consumed=0`。
   这在语义上精确对应 `default:` 分支（未知命令），但命令值就是对的。11 个假设已排除，详见 `docs/03-binder.md`。

2. **kgsl `0x5B` 接口的语义。**
   零参数返回 `EFAULT`，喂真实指针后变成 **`EAGAIN`**——说明它是个读取类接口，数据就绪时真的会返回东西。
   但结构体布局未知，逆向成本高。

---

## 声明

所有操作均在本人自有、数据已清空的设备上进行。仓库中**不包含**任何固件镜像、内核二进制或分区转储。

## License

MIT
