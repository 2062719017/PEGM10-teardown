# 设备零散观察

这台机器上测到的一些属性、行为、和踩坑记录。不成体系，但都是实测的。

## 基础属性

```
ro.product.manufacturer  = OPPO
ro.product.model         = PEGM10
ro.product.device        = OP4E59
ro.product.name          = PEGM10
ro.build.version.release = 13
ro.build.version.sdk     = 33
ro.build.version.security_patch = 2025-06-01
ro.build.display.id      = PEGM10_13.1.0.2101(CN01)
ro.build.fingerprint     = OPPO/PEGM10/OP4E59:13/TP1A.220905.001/R.1e3a263-1-2:user/release-keys
ro.build.type            = user
ro.vendor.oplus.market.name = OPPO Reno5 K 5G
ro.board.platform        = lito          （SM7225 / 骁龙 750G）
ro.zygote                = zygote64_32
ro.boot.verifiedbootstate= green
ro.boot.flash.locked     = 1
ro.boot.veritymode       = enforcing
ro.boot.slot_suffix      = (空，非 A/B)
ro.debuggable            = 0
ro.adb.secure            = 1
```

内核：`4.19.157-perf+`，`#1 SMP PREEMPT Thu Jun 12 22:04:23 CST 2025`，clang 10.0.7。
GPU：Adreno 619（`/sys/class/kgsl/kgsl-3d0/gpu_model` = `Adreno619v1`）。

## USB 枚举的三个阶段

进 EDL 或重启时，USB 上会看到不同形态，别被吓到：

| VID:PID | Windows 识别成 | 含义 |
|---|---|---|
| `22D9:2765` | `OPPO Reno5 K 5G` + `ADB Interface` + `WPD` | 正常系统（MTP + ADB） |
| `18D1:4EE8` | `MIDI function` | **启动过渡态**，约 20 秒，跟 fastboot 无关 |
| `18D1:4EE0` | `AndroidUsbDeviceClass` | **fastbootd**（`is-userspace=yes`） |
| `05C6:9008` | `QUSB_BULK_CID:...` | **EDL** |
| `0000:0002` | 未知 USB 设备（描述符请求失败） | EDL 卡死，需要物理断电 |

`18D1:4EE8` 这个 MIDI 态特别容易误导——一开始以为是进了什么奇怪模式，
实际上只是 Android 启动过程中 gadget 的短暂配置，几十秒后自动变成 `22D9:2765`。

## 进 fastboot / EDL / Recovery 的方式

| 目标 | 方式 | 结果 |
|---|---|---|
| fastboot（真 bootloader） | `adb reboot bootloader` | ❌ ABL 忽略，冷启动系统 |
| fastboot（真 bootloader） | `adb reboot bootonce-bootloader` | ❌ 同上 |
| fastboot（真 bootloader） | 音量键组合 | ❌ 没有这个组合 |
| **fastbootd** | `adb reboot fastboot` | ✅ 进 `18D1:4EE0` |
| **EDL** | `adb reboot edl` | ✅ 进 `05C6:9008`（有时不生效，需重试） |
| Recovery | 音量下 + 电源 | ✅ ColorOS Recovery（选项很少） |
| Recovery | 音量上 + 音量下 + 电源 | ✅ 同上 |
| **强制重启** | **音量上 + 电源** | ✅ **最可靠**，EDL 卡死时用它 |
| 强制重启 | 长按电源 15 秒 | ✅ 有效（EDL 待机耗光电时可能无效） |

**ColorOS Recovery 的选项**（实测）：

```
在线更新
格式化数据分区
重启设备
关机
```

没有 ADB / sideload / 刷机入口。基本没用。

## 安全相关组件

系统里有个服务叫 `anti_root_dialog`：

```
anti_root_dialog: [com.oplus.exsystemservice.antirootdialog.IAntiRootDialog]
```

OPPO 有专门的反 root 检测与提示组件。配合 `oplus_sec`（TEE 密码学应用）、
`abl.elf` 加密，能看出这是一整套设计。

`service list` 里共 **330 个服务**，OPPO 私有服务占很大比例：

```
AtlasService / ISubsysRadio / MMListService / OPLUSExService
OplusLocationManager / additionald / anti_root_dialog
app_compatibility / athenaservice / channel_service
color_screenshot / dynamic_filter / engineer / heimdall
hephaestus_app_data_service / horae / midasd / multimediaDaemon
neuronsystem / obrain / olc / onetrace / oplus_*（约 30 个）
```

## 以 root 身份运行的用户态进程

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
root  1897 vendor-oplus-hardware-engineer-V1-service   ← 工程 HAL
```

这些都是真正的 uid 0。**如果能在这类进程里执行任意代码，就是 root。**

## 设备节点可达性（从 `u:r:shell:s0` 测试）

| 节点 | 权限 / SELinux 标签 | shell 可达 |
|---|---|---|
| `/dev/kgsl-3d0` | `crw-rw-rw-` `gpu_device` | ✅ open + ioctl，**mmap 拒（EACCES）** |
| `/dev/binder` | binderfs | ✅ open + ioctl，**BC 命令拒** |
| `/dev/hwbinder` | binderfs | ✅ open |
| `/dev/vndbinder` | binderfs | ❌ SELinux 拒 |
| `/dev/msm_npu` | `crw-r--r--` `vendor_npu_device` | ✅ open |
| `/dev/ion` | `crw-rw-r--` | ✅ open（但堆配置几乎全关） |
| `/dev/ashmem` | `crw-rw-rw-` | ✅ open |
| `/dev/diag` | `system:vendor_qti_diag` | ❌ DAC 拒 |
| `/dev/qseecom` | `system:drmrpc` | ❌ DAC 拒 |
| `/dev/binder_stats` | `crw-------` root | ❌ |

## `engineer` 服务的接口测绘

```bash
service check engineer        # found
service call engineer N
```

| code | 返回（field2） | 判定 |
|---|---|---|
| 1,2,4,6,8,9,10,14 | `ffffffff` (-1) | 存在，返回失败/需参数 |
| 3,5,7,11,12,15 | `00000000` (0) | 存在，无参即成功 |
| 13 | 单字段返回 | 返回结构不同 |
| **16 及以上** | `ffffffb6` (-74) | **未实现的 transaction code** |

共 **15 个** transaction code。

**副作用验证**：调用 3/5/7/11/12/15 前后对比 `getenforce` / `ro.debuggable` / `ro.secure` /
`ro.boot.verifiedbootstate`，**无任何变化**。是只读方法。

字符串参数测试：传 4000 个 `A` 也正常返回，因为 `service call` 的参数经 libbinder 序列化，
parcel 结构始终合法，**打不到 AIDL 解析层的边界**。

## root HAL 服务调不了

```
dumpsys -l：
  engineer                                          ← Java AIDL，在 system_server
  vendor.oplus.hardware.engineer.IEngineer/default  ← AIDL HAL，在 root 进程 1897

service check "vendor.oplus.hardware.engineer.IEngineer/default"   → found
service call  "vendor.oplus.hardware.engineer.IEngineer/default" 1 → does not exist
```

`check` 认、`call` 不认。带 `/` 的 AIDL HAL 实例名过不了 `service call` 的解析。

要打这个 root HAL，必须自己写 AIDL 客户端——而自写客户端需要裸 binder ioctl，
恰好被 `BC_*` 命令的 `EINVAL` 堵死。

## OPPO 专有 proc 节点

DAC 上都是 `dr-xr-xr-x root:root`（理论上 others 可读），但 SELinux 标签对 `shell` 域全部闭门：

```
/proc/oplus_ke/                          proc
/proc/oplus_secure_common/               proc_oppo_secure_common_file
/proc/oplusVersion/                      proc
/proc/oplus_healthinfo/                  oplus_healthinfo_proc
/proc/oplus_rf/                          proc
/proc/oplus_scheduler/                   proc
/proc/oplusManifest/                     proc
```

`/proc/oplus_ke/` 下面有个 `force_shutdown` 节点，名字挺可疑，但读不了。

## kgsl 的 IOMMU 拓扑

从 `last_kmsg` 里挖到的：

```
iommu: Adding device 3d40000.qcom,kgsl-iommu:gfx3d_user   to group 29
iommu: Adding device 3d40000.qcom,kgsl-iommu:gfx3d_secure to group 30
```

`gfx3d_user` 和 `gfx3d_secure` 是两个独立的 SMMU 组。GPU 内存访问要走 IOMMU 地址转换。
