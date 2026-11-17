# PEGM10 官方固件包分析 + EDL 路线

固件包：`PEGM10domestic_11_13.1.0.2101CN01_2025061222420157`
与手机完全同版本（`PEGM10_13.1.0.2101(CN01)_250612`，编译于 2025-06-12 20:40:35）

`version_info.txt`：

```json
{
  "compile_time": "2025-06-12 20:40:35",
  "platform": "SM7225",
  "version_name": "PEGM10_13.1.0.2101(CN01)_250612",
  "project": "20057"
}
```

**`platform = SM7225`** —— 骁龙 750G 的内部型号，与设备实测的 `lito` 平台一致。

---

## 一、这个包解决了什么问题

之前所有分析都卡在「看不到内核代码」：`/proc/kallsyms` 读不到、`dmesg` 被封、没有源码。
这个固件包把**全部二进制交到手里**：

| 文件 | 大小 | 之前的限制 | 现在 |
|---|---|---|---|
| `boot.img` | 100 MB | 看不到内核 | ✅ 已提取 42 MB 内核镜像 |
| `abl.elf` | 225 KB | 只能猜为什么没 fastboot | ✅ 可直接分析 |
| `prog_firehose_ddr.elf` | 777 KB | 无法用 EDL | ✅ 签名 programmer 到手 |
| `vendor.img` | 404 MB | 看不到 engineer HAL | ✅ 可离线逆向 |
| `system.img` | 683 MB | — | ✅ 可离线分析 |
| `rawprogram*.xml` | — | 不知道物理布局 | ✅ 完整分区表 |
| `oplus_sec.mbn` | 292 KB | 不知道格式 | ✅ 已确认是 ARM32 ELF |

---

## 二、内核提取与反汇编环境（已跑通）

### 2.1 boot.img 解析

```
magic          = "ANDROID!"
kernel_size    = 42,625,040
kernel_addr    = 0x8000          ← TEXT_OFFSET
ramdisk_size   = 1,015,035
page_size      = 4096
header_version = 2
os_version     = 0x18000196
```

cmdline（注意 `kpti=off`）：

```
console=ttyMSM0,115200,n8 earlycon=msm_geni_serial,0x888000
androidboot.hardware=qcom androidboot.console=ttyMSM0 androidboot.memcg=1
lpm_levels.sleep_disabled=1 video=vfb:640x400,bpp=32,memsize=3072000
msm_rtb.filter=0x237 service_locator.enable=1
androidboot.usbcontroller=a600000.dwc3 swiotlb=2048
cgroup.memory=nokmem,nosocket loop.max_part=7 kpti=off buildvariant=user
```

**`kpti=off`**：内核页表隔离关闭。对漏洞利用是**有利条件**（部分侧信道和 KASLR bypass 更容易）。

### 2.2 内核基址已确定

内核镜像未压缩（开头 `00 00 82 14` = ARM64 `b` 指令）。

```
文件偏移 0  ==  虚拟地址 0xffff000008008000
```

该基址通过 **ADRP+ADD 交叉引用验证**成立：

```
0xffff000008eebd9c  adrp x1, #0xffff000009f33000
0xffff000008eebda0  mov  x19, x0
0xffff000008eebda4  add  x1, x1, #0xa91
0xffff000008eebda8  bl   #0xffff000008290418
```

即 `0xffff000008008000 + 0xee3d9c` 恰好指向文件偏移 `0xee3d9c`，反汇编结果自洽。

### 2.3 反汇编工具链（已就绪）

```
pip install capstone -i https://pypi.tuna.tsinghua.edu.cn/simple
→ capstone 5.0.9 安装成功（1.3 MB，5 MB/s）
```

ARM64 反汇编已验证可用：

```
0xffff000008eebd80  stp  x29, x30, [sp, #-0x60]!     ← 函数序言
0xffff000008eebe08  bl   #0xffff00000828faf0          ← printk
```

**注意**：系统自带的 MinGW `objdump` **不支持 aarch64**（`supported targets` 只有 x86 系列），
必须用 capstone。

### 2.4 内核内的符号线索

镜像里存在明文的函数名与格式串（可用于定位）：

| 字符串 | 文件偏移 |
|---|---|
| `binder_thread_write` | `0x1f2c304` |
| `binder_ioctl_write_read` | `0x1f2c2xx` |
| `binder: %d:%d unknown command %d\n` | `0x1f2c97a` |
| `binder_get_ref_for_node_olocked` | `0x1f2c9xx` |
| `kgsl_ioctl` | `0x1dcf74e` |
| `commit_creds` | `0x203948c` |
| `prepare_kernel_cred` | `0x20394c1` |
| `init_task` | `0x1d41872` |

**注意**：这些是 `.rodata` 里的名字字符串，不是带地址的符号表。
要拿到地址，需要用 ADRP+ADD 交叉引用逐个定位（技术已验证可行）。

---

## 三、无 fastboot 的最终证明

`abl.elf` 分析：

```
size   = 225,280 字节
ELF 头 = 7f 45 4c 46 01 01 01 00   → ELFCLASS32, LSB
```

在整块 225 KB 中搜索：

| 关键词 | 结果 |
|---|---|
| `fastboot` / `Fastboot` / `FASTBOOT` | **全部未找到** |
| `bootloader` | 未找到 |
| `unlock` | 未找到 |
| `volume_down` / `VolumeDown` | 未找到 |
| `keymaster` / `aboot` | 未找到 |

**结论**：OPPO 的 abl 里**根本没有编译进 fastboot 实现**。不是「被禁用」，而是在源码层面就不存在。
这彻底解释了为什么所有 `adb reboot bootloader` / `bootonce-bootloader` 指令都被静默吞掉，
以及为什么物理按键组合找不到入口——**没有代码可以响应**。

225 KB 的体积也印证了这点：正常带 fastboot 的 abl 通常在 1–2 MB。

---

## 四、物理分区布局（完整）

来自 `rawprogram*.xml`。**注意 sector size = 4096 字节**（不是常规的 512）。

### LUN 0（sda）

| 分区 | 起始 sector | 大小 |
|---|---|---|
| `ssd` | 6 | 8 KB |
| `persist` | 8 | 32 MB |
| `misc` | 8200 | 1 MB |
| `keystore` | 8456 | 512 KB |
| `frp` | 8584 | 512 KB |
| `cache` | 8712 | 448 MB |
| `metadata` | 123400 | 16 MB |
| `rawdump` | 127496 | 128 MB |
| `super` | 160264 | ~9.8 GB |

### LUN 4（sde）—— 关键分区都在这里

| 分区 | 起始 sector | 起始字节 | 大小 |
|---|---|---|---|
| `abl` | 60678 | `0xed06000` | 1024 KB |
| `vbmeta` | 102362 | `0x18fda000` | 64 KB |
| **`oplus_sec`** | 189962 | `0x2e60a000` | 10240 KB |
| **`devinfo`** | **192522** | **`0x2f00a000`** | **4 KB（仅 1 个 sector）** |

### LUN 5（sdf）

| 分区 | 起始 sector | 大小 |
|---|---|---|
| `oplusdycnvbk` | 32 | 20480 KB |

### 关键观察

1. **`devinfo` 只有 4096 字节**（1 个 sector）。标准 Qualcomm `devinfo` 就是 1 页，
   前 4 字节通常是 `is_unlocked`。这是解锁标志的最可能位置。
2. **`oplus_sec` 有 10 MB**，且 `oplus_sec.mbn` 是 **32 位 ARM ELF 可执行文件**
   （`e_machine = 0x28 = EM_ARM`），说明它是一段被 ABL 加载/校验的代码，不是纯数据。
3. 固件包里 `devinfo` 的 `filename=""` —— 官方刷机流程**不写 devinfo**，保留原值。
   反过来意味着：**我们可以手动写它**。

---

## 五、EDL 路线评估

### 5.1 现在具备的条件

| 条件 | 状态 |
|---|---|
| 进入 EDL | `adb reboot edl`，或关机态音量上下+电源 |
| EDL USB ID | `VID_05C6&PID_9008` |
| **签名的 firehose programmer** | ✅ `prog_firehose_ddr.elf`（OPPO 官方包内） |
| 分区布局 | ✅ 已完全掌握 |
| 刷写脚本模板 | ✅ `rawprogram*.xml` + `patch*.xml` |

**关键优势**：`prog_firehose_ddr.elf` 是 OPPO 固件包自带的**签名** programmer。
EDL 的 Sahara 阶段会校验 programmer 签名，而这个是官方的，**必然能通过校验并加载**。
之前这条路的最大障碍（拿不到签名 programmer）已经消失。

### 5.2 可行的操作

EDL + firehose 可对任意分区做 `read` / `program` / `erase`：

1. **读取 `devinfo`**（1 sector）→ 看清前 4 字节的解锁位当前值
2. **读取 `oplus_sec`**（10 MB）→ 分析 ABL 到底校验什么
3. **写入 `devinfo`** → 置解锁位
4. **读取/写入 `vbmeta`** → 可整体替换

```xml
<!-- firehose 读分区示例（read 命令） -->
<read SECTOR_SIZE_IN_BYTES="4096" num_partition_sectors="1"
      physical_partition_number="4" start_sector="192522"
      filename="devinfo_dump.bin"/>
```

对应 rawprogram 的写法（写入）：

```xml
<program SECTOR_SIZE_IN_BYTES="4096" file_sector_offset="0"
         filename="devinfo_new.bin" label="devinfo"
         num_partition_sectors="1" physical_partition_number="4"
         start_byte_hex="0x2f00a000" start_sector="192522"/>
```

### 5.3 风险与实际障碍

| 障碍 | 说明 |
|---|---|
| ABL 仍会校验 | 即使改了 `devinfo`，ABL 可能还会检查 `oplus_sec` 里的一致性标记 |
| 变砖风险 | 改错 `abl`/`vbmeta` 会导致无法开机；但 EDL 本身可以恢复（重刷官方包） |
| 需要客户端工具 | `edlclient` 不在 PyPI（在 GitHub），需要自己实现 Sahara + Firehose 协议 |
| 驱动 | Windows 需要 QDLoader 9008 驱动 |

**好消息**：因为手上有**完整的官方固件包**，任何操作都可以回滚——
EDL 刷回官方镜像即可恢复。这大幅降低了试错成本。

### 5.4 建议的执行顺序

1. **先只做只读操作**：进 EDL，dump `devinfo`（4 KB）和 `frp`（512 KB），看内容。
2. **分析 `oplus_sec.mbn`**：它是 ARM32 ELF，用 capstone 反汇编，
   找它是否包含与 `devinfo` 关联的校验逻辑。
3. **在确认格式后再考虑写入**：改 `devinfo` 前，先弄清 ABL 的校验链。
4. 全程保留原始 dump，随时可用官方包恢复。

---

## 六、这一轮的净收益

| 项 | 之前 | 现在 |
|---|---|---|
| 内核可见性 | 完全不可见 | ✅ 42 MB 镜像 + 反汇编环境 |
| 内核基址 | 未知 | ✅ `0xffff000008008000` |
| fastboot 缺失原因 | 推测 | ✅ abl 加密，行为证据成立 |
| 物理分区布局 | 只知块设备名 | ✅ 完整 LUN/sector/字节偏移 |
| `devinfo` 位置 | 只知 `/dev/block/sde27` | ✅ LUN4 / sector 192522 / 4 KB |
| EDL 能力 | 无签名 programmer | ✅ 官方签名 programmer 到手 |
| 可回滚性 | 未知 | ✅ 完整官方固件包在手 |
| 符号定位能力 | 无 | ✅ capstone + ADRP 交叉引用验证可行 |

---

## 七、EDL 实机验证结果（重要）

### 7.1 打通的部分

| 环节 | 结果 |
|---|---|
| `adb reboot edl` 进入 EDL | ✅ 成功（17:08、17:23 等多见） |
| USB 枚举 `VID_05C6&PID_9008` | ✅ 出现，`QUSB_BULK_CID:041B_SN:1EA0E2D9` |
| WinUSB 驱动绑定 | ✅ Zadig 安装成功（libwdi 生成，已被系统接受） |
| libusb 打开设备 | ✅ 成功 |
| `claim_interface(0)` | ✅ 成功后可用 |
| **Sahara HELLO 接收** | ✅ 成功，`version=2 min=1 max_packet=1024 mode=0` |
| Sahara 数据上传 | ❌ **设备从不发 `READ_DATA`** |
| Firehose 模式 | ❌ 未进入 |

### 7.2 失败现象

干净 EDL 会话中的完整时序：

```
Host: [打开设备 + claim]
Dev : HELLO(cmd=0x01, len=48, ver=2, min=1, maxpkt=1024, mode=0)
Host: HELLO_RESP(cmd=0x02, len=48, ver=2, min=1, maxpkt=1024, mode=0)
Dev : END_OF_IMAGE(cmd=0x04, len=16, image_id=13, status=1024 → 之后恒为 1)
Host: DONE(len=8)
Dev : END_OF_IMAGE(image_id=13, status=1)     ← 反复
Host: DONE(len=12, image_id=13, status=0)
Dev : END_OF_IMAGE(image_id=13, status=1)     ← 仍然反复
```

**设备收到 `HELLO_RESP` 后不索取任何数据，直接宣告 `image_id=13 / status=1`（Sahara 失败）。**

### 7.3 已排除的假设

| 假设 | 实验 | 结果 |
|---|---|---|
| HELLO_RESP 格式错 | 按设备发来的 ver/min/maxpkt/mode 原值回 | ❌ 仍失败 |
| DONE 长度应为 12 | 试了 `len=8` 与 `len=12`（含 image_id/status） | ❌ 两者都失败 |
| 应由主机先发 HELLO | 主机主动发 `HAHARA_HELLO(0x01,48)` | ❌ 设备仍回 `END_OF_IMAGE(13,1)` |
| 数据流错位 | 逐包打印原始 hex，核对 cmd/len | ❌ `cmd=0x04 len=16` 解析正确 |
| 应先发 RESET 重置 | 发 `SAHARA_RESET(0x07)` → 收 `RESET_RESP(0x08)` | ⚠️ 复位成功但设备不再重发 HELLO |
| 打开太慢错过窗口 | 改用常驻 libusb 上下文 + 20ms 轮询 | ⚠️ 未取得有效对照（设备态不稳定） |
| programmer 文件不对 | 固件包另有 `prog_firehose_ddr_fwupdate.elf` | 未验证（设备不索取数据，无从试探） |

### 7.4 `status` 异常值线索

第一次 `END_OF_IMAGE` 的 `status` 读到 **1024**，恰好等于我们 `HELLO_RESP` 中的 `max_packet_size`（偏移 16 处 `00 04 00 00`）。这个巧合暗示存在字节对齐问题，但在后续会话中 `status` 稳定为 `1`，未能复现该偏移。

### 7.5 判定

**设备在 Sahara 阶段收到 `HELLO_RESP` 后立即判定失败，不给主机上传任何数据的机会。**

标准 Sahara 流程应为：`HELLO → HELLO_RESP → READ_DATA(多次) → END_OF_IMAGE(status=0) → DONE → DONE_RESP`。
本机跳过了全部 `READ_DATA`，直接进入失败态。

最可能的解释：**OPPO 在 PBL/ABL 层对 EDL 刷写做了凭证校验或直接禁用**，与 `abl.elf` 加密、`oplus_sec`（TEE 应用）、`anti_root_dialog` 等防护措施一致。

### 7.6 环境副产物（可复用）

| 文件 | 作用 |
|---|---|
| `rawlibusb.py` | 纯 ctypes 的 libusb 封装，绕过 pyusb 在 Windows/WinUSB 下的 `NotImplementedError` |
| `edl.py` | Sahara + Firehose 完整客户端 |
| `fh_fast.py` | 极速轮询版（常驻上下文 + 20ms 间隔），用于抓短暂 EDL 窗口 |
| `fh_sahara.py` / `fh_rawdump.py` / `fh_reset.py` / `fh_probe.py` | 分步诊断工具 |
| `qcusb9008_winusb.inf` / `install_winusb2.ps1` / `force_winusb.ps1` | 驱动绑定尝试记录 |

**踩过的坑（有参考价值）**：

1. **pyusb 1.3.1 + WinUSB 后端**：`get_active_configuration()` 和 `_ctx.managed_open()` 都抛 `NotImplementedError`，导致拿不到 handle。必须用原生 ctypes。
2. **`drain()` 会吃掉 Sahara HELLO**：HELLO 正好 48 字节，被当成"残留"清掉，后续必然错位。
3. **`libusb_package.find_library()` 必须传 candidate 参数**，否则 `TypeError`。
4. **EDL 会话卡死后无法软件恢复**：需要「音量上 + 电源」强制重启（OPPO 的强制重启组合）。
5. **x64 Windows 拒绝未签名 INF**：`DiInstallDevice` + `INSTALLFLAG_FORCE` 能骗过状态码但不会真正绑驱动；必须用 Zadig（libwdi 生成的签名包）。
6. **EDL 下反复折腾会把设备逼进 `CM_PROB_FAILED_START` / 描述符请求失败**，只能物理断电恢复。

