# 物理分区表（PEGM10）

来源：官方固件包里的 `rawprogram0..5.xml`（Qualcomm QFIL 格式）。

> ⚠️ **sector size = 4096 字节**，不是常规的 512。这是 UFS 设备的典型配置。
> 换算字节偏移时别搞错。

## LUN 0（块设备 `sda`）

| 分区 | 起始 sector | 起始字节 | 大小 |
|---|---|---|---|
| `ssd` | 6 | `0x6000` | 8 KB |
| `persist` | 8 | `0x8000` | 32 MB |
| `misc` | 8200 | `0x2008000` | 1 MB |
| `keystore` | 8456 | `0x2108000` | 512 KB |
| `frp` | 8584 | `0x2188000` | 512 KB |
| `cache` | 8712 | `0x2208000` | 448 MB |
| `metadata` | 123400 | `0x1e208000` | 16 MB |
| `rawdump` | 127496 | `0x1f208000` | 128 MB |
| `super` | 160264 | `0x27208000` | ~9.8 GB（动态分区容器） |
| `userdata` | 2727432 | `0x299e08000` | 剩余空间 |

## LUN 4（块设备 `sde`）—— 关键分区都在这里

| 分区 | 起始 sector | 起始字节 | 大小 | 说明 |
|---|---|---|---|---|
| `abl` | 60678 | `0xed06000` | 1024 KB | Bootloader（**代码段加密**，熵 7.884） |
| `vbmeta` | 102362 | `0x18fda000` | 64 KB | AVB 校验元数据 |
| `oplus_sec` | 189962 | `0x2e60a000` | 10240 KB | **TEE 密码学应用**（32 位 ARM ELF，非数据） |
| **`devinfo`** | **192522** | **`0x2f00a000`** | **4 KB** | **1 个 sector，Qualcomm 解锁标志位通常在偏移 0** |

## LUN 5（块设备 `sdf`）

| 分区 | 起始 sector | 起始字节 | 大小 |
|---|---|---|---|
| `oplusdycnvbk` | 32 | `0x20000` | 20480 KB |

## 从系统里看到的块设备映射

```
/dev/block/by-name/devinfo        → /dev/block/sde27
/dev/block/by-name/oplus_sec      → /dev/block/sde26
/dev/block/by-name/oplusdycnvbk   → /dev/block/sdf2
/dev/block/by-name/vbmeta         → /dev/block/sde18
/dev/block/by-name/vbmeta_system  → /dev/block/sde16
/dev/block/by-name/vbmeta_vendor  → /dev/block/sde17
/dev/block/by-name/abl            → /dev/block/sde8
/dev/block/by-name/frp            → /dev/block/sda5
/dev/block/by-name/misc           → /dev/block/sda3
/dev/block/by-name/super          → /dev/block/sda9
/dev/block/by-name/userdata       → /dev/block/sda10
```

## 几个值得注意的点

### `devinfo` 只有 4 KB

标准 Qualcomm `devinfo` 就是 1 页（4096 字节），前 4 字节通常是 `is_unlocked`。

而固件包里 `devinfo` 的 `filename=""`——**官方刷机流程不写它，保留原值**。
反过来意味着它是"可以手动改"的。

不过这台机器上改 `devinfo` 未必有用——ABL 可能还校验别处（这台机器 `oplus_sec` 已确认是 TEE 应用，
与解锁无关，所以真正的校验点还没找到；`abl.elf` 加密，静态分析不了）。

### `oplus_sec` 不是解锁校验分区

分区名容易误导。反汇编确认它是跑在 QSEE 里的 TEE 密码学引擎（`cryptoeng`），
提供加解密、签名验签服务，跟 bootloader 解锁没关系。

### `super` 是动态分区容器

`is-logical:*:yes` 那一长串（`system` / `vendor` / `product` / `my_*` 等）都在 `super` 里面。
`fastbootd` 能管这些逻辑分区，但管不了 `devinfo`/`abl`/`vbmeta` 这类物理分区。

### 非 A/B 设备

```
slot-count: 0
current-slot: (空)
has-slot:*: no   （全部）
```

单槽，没有 A/B 分区。所以不存在"刷到另一个槽再切过去"这种回退手段。

### fastbootd 能看到的逻辑分区大小

```
is-logical:product:yes      partition-size:product:0x279000      (~2.5 MB)
is-logical:my_product:yes   partition-size:my_product:0x1F1BD000 (~508 MB)
```

`product` 只有 2.5 MB 有点反直觉，但这是 OPPO 的 `my_product` 拆分布局导致的。
