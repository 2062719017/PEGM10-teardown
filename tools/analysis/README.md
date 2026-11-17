# tools/analysis — 内核镜像与固件包分析

| 文件 | 用途 |
|---|---|
| `kallsyms_parse.py` | 从内核镜像还原 kallsyms 压缩符号表（实验性） |
| `find_kallsyms.py` | 用统计特征定位 `kallsyms_token_table` |
| `xref_adrp.py` | ★ 通过 `ADRP+ADD` 交叉引用在 ARM64 内核里定位函数 |
| `analyze_mbn.py` | 解析 ARM32/ARM64 ELF（`.mbn` / `.elf`），提取段表与关键词字符串 |
| `pe_res.py` | 列 Windows PE 的资源目录（用于从 Zadig 里找内嵌驱动） |

## `xref_adrp.py` — 最实用的那个

**原理**：ARM64 用 PC 相对寻址加载地址，典型序列：

```
ADRP Xd, page        ; Xd = (PC & ~0xFFF) + (imm << 12)
ADD  Xd, Xd, #off    ; Xd += off  -> 指向目标
```

反向搜索：给定目标字符串的虚拟地址，扫描全镜像找能算出该地址的 `ADRP+ADD` 对。

```bash
python xref_adrp.py kernel.bin 0x1f2c97a --base 0xffff000008008000
```

## 确定内核基址

arm64 内核 Image 的标准布局：

```
文件偏移 0  ==  _text  ==  KIMAGE_VADDR + TEXT_OFFSET
```

`TEXT_OFFSET` 从 `boot.img` 头里读（`kernel_addr` 字段，这台机器是 `0x8000`）。
`KIMAGE_VADDR` 通常是 `0xffff000008000000`。

所以：**`文件偏移 0 = 0xffff000008008000`**。

验证方法：找一条已知的格式串在 `.rodata` 的偏移，算出它的虚拟地址，
扫描镜像找 `ADRP+ADD` 引用，反汇编那段代码看语义是否自洽（能看到标准函数序言
`stp x29, x30, [sp, #-0x60]!` 和 `bl` 调用 `printk` 就说明对了）。

## 从 boot.img 提取内核

```python
# Android boot image v2 头
kernel_size    = struct.unpack_from('<I', hdr, 8)[0]     # 0x08
ramdisk_size   = struct.unpack_from('<I', hdr, 16)[0]    # 0x10
page_size      = struct.unpack_from('<I', hdr, 36)[0]    # 0x24
header_version = struct.unpack_from('<I', hdr, 40)[0]    # 0x28

# kernel 从 page_size 偏移开始
# 提取时不要一次读 42MB 到内存再写，分块读
```

检查是否为未压缩 Image：前 4 字节应是 ARM64 的 `b` 指令（`00 00 82 14` 对应 `b +0x8000`）。

## `analyze_mbn.py` 的用法

```bash
python analyze_mbn.py oplus_sec.mbn
```

输出 ELF 头、program headers、section headers，以及按关键词过滤的可打印字符串。
关键词表在文件顶部 `KEYWORDS`，按需改。

**判断 `.mbn` 是代码还是数据**：看 `e_machine`。
`40` = `EM_ARM`（32 位 ARM 代码），`183` = `EM_AARCH64`，其他值基本是数据或加密内容。

## 熵值判断

分析固件里的二进制前，先算熵：

```python
import collections, math
cnt = collections.Counter(data)
ent = -sum((c/len(data))*math.log2(c/len(data)) for c in cnt.values() if c)
```

| 熵值 | 含义 |
|---|---|
| < 7.0 | 明文代码/数据，可以做字符串搜索 |
| 7.0 – 7.9 | 可能是压缩（找 `LZMA`/`gzip`/`lz4`/`zstd` 头） |
| **> 7.85** | **加密**，字符串搜索无意义 |

本机的 `abl.elf` 实测 **7.884**——所以"搜不到 `fastboot` 字符串"不能当证据。

## 镜像里能搜到的符号线索

内核 `.rodata` 里有大量明文函数名和格式串（kallsyms 的 token 表、`__func__` 用法、调试打印），
可以当作定位锚点：

```
binder_thread_write                    0x1f2c304
binder: %d:%d unknown command %d\n     0x1f2c97a   ← binder_thread_write 的 default 分支
kgsl_ioctl                             0x1dcf74e
commit_creds                           0x203948c
prepare_kernel_cred                    0x20394c1
init_task                              0x1d41872
```

找到锚点之后用 `xref_adrp.py` 反查引用它的代码位置。

⚠️ **注意**：这些是名字字符串，不是带地址的符号表。完整的 `kallsyms_offsets` 需要自己解析压缩表，
`kallsyms_parse.py` 是实验性实现，在这台机器的镜像上**没有成功定位**（token_table 的统计特征不明显）。
