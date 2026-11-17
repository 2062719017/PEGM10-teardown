# tools/edl — Qualcomm EDL (9008) 客户端

纯 Python 实现的 Sahara + Firehose 协议，不依赖 `edlclient`（它不在 PyPI）。

## 为什么自己写

- `edlclient` 只在 GitHub，不在 PyPI
- **pyusb 在 Windows/WinUSB 后端下直接瘫痪**（`get_active_configuration` 抛 `NotImplementedError`）
- 自己实现反而简单，protol 就两层

## 文件说明

| 文件 | 用途 |
|---|---|
| **`rawlibusb.py`** | ★ 纯 ctypes 的 libusb 封装，绕开 pyusb 的描述符层 |
| `edl.py` | Sahara + Firehose 完整客户端（推荐入口） |
| `edl_client.py` | 早期版本（用 pyusb，保留了作为对照） |
| `fh_fast.py` | **极速轮询版**——常驻 libusb 上下文 + 20ms 间隔，用于抓短暂 EDL 窗口 |
| `fh_sahara.py` | Sahara 分步诊断（含 DONE 长度 8/12 两种变体） |
| `fh_rawdump.py` | 纯原始字节流 dump，不解析 |
| `fh_reset.py` | 发 `SAHARA_RESET` 并观察是否重发 HELLO |
| `fh_probe.py` | 发 `<configure>` / `<read>` 试探是否已进入 Firehose |
| `fh_wait_hello.py` | 只等 HELLO |

## 前置条件

### 1. 驱动：必须绑到 WinUSB

Windows 上 x64 强制驱动签名，自定义 INF 装不上。**用 [Zadig](https://zadig.akeo.ie/)**：

1. `Options → List All Devices`
2. 选择 `QUSB_BULK_CID:...`（EDL 里的设备）
3. 驱动目标选 `WinUSB (v6.1.7600.16385)`
4. 点 `Install Driver`

验证是否真的绑上——**看注册表的 `Service` 项**，别信设备管理器图标：

```powershell
$k = 'HKLM:\SYSTEM\CurrentControlSet\Enum\USB\VID_05C6&PID_9008\<instance>'
(Get-ItemProperty -Path $k).Service    # 应该是 "WinUSB"
```

`tools/drivers/` 里保留了所有失败的尝试记录，供参考。

### 2. 依赖

```bash
pip install pyusb libusb-package
```

`libusb-package` 自带 `libusb-1.0.dll`，不需要单独装 libusb。

## 用法

```bash
# 只握手，验证设备是否响应
python edl.py --programmer prog_firehose_ddr.elf --handshake

# 上传 programmer 并读分区
python edl.py --programmer prog_firehose_ddr.elf --read 4 192522 1 --out devinfo.bin
#                                                          LUN 起始扇区 扇区数
```

`--read` 的三个参数对应 Firehose 的 `<read>` 命令：

```xml
<read SECTOR_SIZE_IN_BYTES="4096" num_partition_sectors="1"
      physical_partition_number="4" start_sector="192522" />
```

## 时序很关键

`adb reboot edl` 之后设备只枚举很短一段时间。**必须先启动客户端等设备，再触发 EDL**：

```powershell
# 1. 后台启动等待器
$job = Start-Job { python fh_fast.py wait }

# 2. 再触发
adb reboot edl

# 3. 等结果
Wait-Job $job
```

反过来的话，等 adb 命令返回再启动脚本，设备可能已经退出 EDL 了。

## 本仓库中未成功的部分

在这台 PEGM10 上，Sahara 卡在一个无法解释的地方：

```
Host: 打开设备 + claim
Dev : HELLO(ver=2, min=1, maxpkt=1024, mode=0)     ← 握手正常
Host: HELLO_RESP                                    ← 参数按设备发来的原值回
Dev : END_OF_IMAGE(image_id=13, status=1)           ← 立刻失败
Host: DONE(len=8 / len=12)                          ← 两种都试过
Dev : END_OF_IMAGE(image_id=13, status=1)           ← 反复
```

**设备一个字节的 `READ_DATA` 都不发**，所以我们从没机会上传任何数据。

排除过的假设（详见 `../../docs/04-firmware-edl.md`）：
HELLO_RESP 格式、DONE 长度 8/12、主机主动发 HELLO、数据流错位、先发 RESET、打开太慢、programmer 文件选错。

推测是 OPPO 在 PBL/ABL 层对 EDL 刷写做了凭证校验或直接禁用。
**如果你在别的机型上遇到同样现象，大概率是同一个原因。**

## ⚠️ 安全注意事项

1. **先看电量**：`adb shell dumpsys battery | grep level`，30% 以下别玩
2. **不要在一个会话里反复试命令**：Sahara 状态机会崩，崩了只能物理断电
3. **EDL 不会自己退出**：需要「音量上 + 电源」或长按电源 15 秒强制重启
4. **准备好官方固件包**：万一进了 EDL 出不来，有包才能救
