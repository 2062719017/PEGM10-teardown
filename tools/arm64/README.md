# tools/arm64 — 零编译器手搓 ARM64 ELF

环境里没有 NDK（下载速率 0.03 MB/s，不现实），所以这套探针是**用 Python 生成 ARM64 机器码 + 手工构造 ELF** 的。

产物 244–600 字节，不链接 libc，直接发系统调用。`adb push` 过去 `chmod 755` 就能跑。

## 为什么这么做

- NDK r27c 是 690 MB，按 0.03 MB/s 要 6 小时
- 国内镜像更慢（腾讯镜像实测 0.02 MB/s）
- `zig` / `clang` 都缺，MinGW 的 gcc 只能出 x86
- `objdump` 不支持 aarch64

于是只能自己拼机器码。好处是对指令级别的控制非常精确——测 ioctl 时连结构体每个字段都能指定。

## 文件说明

| 文件 | 用途 |
|---|---|
| `mkelf.py` | 最小 `openat + ioctl + exit`，用退出码回传达 errno |
| `mkelf_call.py` | **通用调用器**——任意请求号 + 结构体字段表 |
| `mkelf_scan.py` | ioctl 表枚举器（循环 nr `0x01..0x5F`） |
| `mkelf_ctx.py` | kgsl context type 穷举器 |
| `mkelf_full.py` | 带完整 `kgsl_device_getproperty` 的读数探针 |
| `mkelf_alloc.py` | `KGSL_GPUMEM_ALLOC_ID` 合法调用 |
| `mkelf_chain.py` | 单进程 alloc → get_info → mmap 全链，带 A/B/C/D 阶段标记 |
| `mkelf_binder.py` | binder 可达性 + mmap 参数扫描 |
| `mkelf_binder_txn.py` | binder 事务构造器（`--hex` / `--wsize` / `--withread` / `--nommap`） |
| `mkelf_binder_cmd.py` | 通用 binder ioctl 探测器 |
| `mkelf_binder_ioctl_size.py` | `binder_write_read` 结构体尺寸扫描 |

## 用法

最常用的是 `mkelf_call.py`：

```bash
# 语法：python mkelf_call.py <输出名> <请求号> <结构体大小> "<字段表>"
# 字段表格式： 偏移:值:宽度(1|4|8)[,偏移:值:宽度...]

# 申请 1MB GPU 内存（size 字段在偏移 8）
python mkelf_call.py probe 0xC0200934 32 "8:0x100000:8"

# 往结构体第 0 字段塞一个指向结构体自身的指针（特殊值 sp）
python mkelf_call.py probe 0xC0300949 48 "0:sp:8"
```

部署运行：

```powershell
adb push probe /data/local/tmp/probe
adb shell 'chmod 755 /data/local/tmp/probe; /data/local/tmp/probe > /data/local/tmp/out.bin; echo EXIT=$?'
adb pull /data/local/tmp/out.bin
```

**退出码判读**：`256 - 退出码 = errno`。
`ENOTTY(25)` = 命令未注册，`EINVAL(22)` = 已注册但参数被拒，`EFAULT(14)` = 已注册且进入 `copy_from_user`，
`EACCES(13)`/`EPERM(1)` = 权限拒绝。

## ⚠️ 最重要的注意事项

**生成完必须反汇编核对。**

这套工具踩过一个 `movz` 立即数截断的坑，伪造了三条"内核拒绝"的假结论（详见 `../../pitfalls/README.md` 第一条）。

验证方法：

```python
import capstone, struct
md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
for i in md.disasm(code_bytes, 0x400000):
    print(f'0x{i.address:08x}  {i.mnemonic}  {i.op_str}')
```

## 关于 ELF 构造

用 `PT_LOAD` 单段，flags 用 `R|X`（5）而不是 RWX——代码放在只读可执行段里，
字符串和结构体都放栈上，这样能避开某些 SELinux 策略对 `execmod` 的限制。

`p_offset = 0`, `p_vaddr = 0x400000`, `entry = 0x400000 + 0x78`（64 字节 ELF 头 + 56 字节程序头）。

## 已知局限

- 只能静态链接，没有 libc（`printf` 之类得自己拼或者用 `write` 系统调用）
- 复杂逻辑（循环、条件分支）用这套 DSL 写起来很痛苦，超过 100 行指令建议换真编译器
- 不支持重定位，所有地址都得手算
