#!/usr/bin/env python3
"""
mkelf_call.py — 通用 ARM64 ioctl 调用生成器（零编译依赖）

按字段表初始化一个结构体，调用指定 ioctl，再把结构体原样 dump 到 stdout。

用法：
    python mkelf_call.py <输出文件> <ioctl请求号> <结构体大小> "<字段表>"

    字段表格式： off:value:width[,off:value:width...]
        off   - 结构体内偏移（字节）
        value - 立即数（支持 0x 前缀），或特殊值 sp（写入 sp+base_off 的地址）
        width - 1 / 4 / 8，对应 strb / str(32) / str(64)

    未列出的字节保持栈上的原值（调用前会整体清零）。

示例：
    # KGSL_GPUMEM_ALLOC_ID，申请 1MB
    python mkelf_call.py p 0xC0200934 32 "8:0x100000:8"

    # 往结构体第 0 字段塞一个指向结构体自身的指针
    python mkelf_call.py p 0xC0300949 48 "0:sp:8"

    # KGSL_DRAWCTXT_CREATE，创建绘图上下文
    python mkelf_call.py p 0xC0080913 8 "0:0:4,4:0:4"

    # KGSL_GPUOBJ_ALLOC，申请 4KB GPU 对象
    python mkelf_call.py p 0xC0280945 40 "0:0x1000:8,8:0:8,16:0:8,24:0:8,32:0:4"

退出码 = ioctl 返回值映射（256 - 退出码 = errno）。
"""

import struct
import sys

def movz64(rd, imm16, shift=0):
    return 0xD2800000 | ((shift // 16) << 21) | ((imm16 & 0xFFFF) << 5) | rd

def movk64(rd, imm16, shift=0):
    return 0xF2800000 | ((shift // 16) << 21) | ((imm16 & 0xFFFF) << 5) | rd

def movz32(rd, imm16, shift=0):
    return 0x52800000 | ((shift // 16) << 21) | ((imm16 & 0xFFFF) << 5) | rd

def movk32(rd, imm16, shift=0):
    return 0x72800000 | ((shift // 16) << 21) | ((imm16 & 0xFFFF) << 5) | rd

def add_imm(rd, rn, imm12):
    return 0x91000000 | ((imm12 & 0xFFF) << 10) | ((rn & 0x1F) << 5) | (rd & 0x1F)

def stp(rt, rt2, rn, off):
    return 0xA9000000 | (((off // 8) & 0x7F) << 15) | ((rt2 & 0x1F) << 10) | ((rn & 0x1F) << 5) | (rt & 0x1F)

def str64(rt, rn, off):
    return 0xF9000000 | (((off // 8) & 0xFFF) << 10) | ((rn & 0x1F) << 5) | (rt & 0x1F)

def str32(rt, rn, off):
    return 0xB9000000 | (((off // 4) & 0xFFF) << 10) | ((rn & 0x1F) << 5) | (rt & 0x1F)

def str8(rt, rn, off):
    return 0x39000000 | ((off & 0xFFF) << 10) | ((rn & 0x1F) << 5) | (rt & 0x1F)

SVC = 0xD4000001


def load_const(ins, reg, value, wide):
    if wide:
        ins.append(movz64(reg, value & 0xFFFF))
        for sh in (16, 32, 48):
            part = (value >> sh) & 0xFFFF
            if part:
                ins.append(movk64(reg, part, sh))
    else:
        ins.append(movz32(reg, value & 0xFFFF))
        part = (value >> 16) & 0xFFFF
        if part:
            ins.append(movk32(reg, part, 16))


def build(req, ssize, fields, base_off=32):
    path = b"/dev/kgsl-3d0\x00".ljust(16, b"\x00")
    lo = struct.unpack("<Q", path[0:8])[0]
    hi = struct.unpack("<Q", path[8:16])[0]

    frame = base_off + ((ssize + 15) // 16) * 16 + 16
    frame = ((frame + 15) // 16) * 16
    if frame > 4095:
        raise SystemExit("frame too large")

    ins = []
    ins.append(0xD1000000 | ((frame & 0xFFF) << 10) | (31 << 5) | 31)   # sub sp, sp, #frame

    # 路径
    ins.append(movz64(9, lo & 0xFFFF))
    for sh in (16, 32, 48):
        ins.append(movk64(9, (lo >> sh) & 0xFFFF, sh))
    ins.append(movz64(10, hi & 0xFFFF))
    for sh in (16, 32, 48):
        ins.append(movk64(10, (hi >> sh) & 0xFFFF, sh))
    ins.append(stp(9, 10, 31, 0))

    ins.append(0x92800C60)              # movn x0, #99 (AT_FDCWD)
    ins.append(add_imm(1, 31, 0))       # mov x1, sp
    ins.append(0xD2800042)              # movz x2, #2 (O_RDWR)
    ins.append(0xD2800708)              # movz x8, #56 (openat)
    ins.append(SVC)
    ins.append(0x91000015)              # mov x21, x0 (fd)
    ins.append(0xF100001F)              # cmp x0, #0
    b_open = len(ins); ins.append(0)

    # 清零结构体
    nz = ((ssize + 15) // 16) * 16
    for o in range(0, nz, 16):
        ins.append(stp(31, 31, 31, base_off + o))

    # 填字段
    for (off, value, width) in fields:
        if value == "sp":
            ins.append(add_imm(9, 31, base_off))   # mov x9, sp+base_off
        else:
            load_const(ins, 9, value, width == 8)
        if width == 8:
            ins.append(str64(9, 31, base_off + off))
        elif width == 4:
            ins.append(str32(9, 31, base_off + off))
        elif width == 1:
            ins.append(str8(9, 31, base_off + off))

    # ioctl
    ins.append(0x910002A0)              # mov x0, x21
    ins.append(movz32(1, req & 0xFFFF))
    ins.append(movk32(1, (req >> 16) & 0xFFFF, 16))
    ins.append(add_imm(2, 31, base_off))  # add x2, sp, #base_off
    ins.append(0xD28003A8)              # movz x8, #29 (ioctl)
    ins.append(SVC)
    ins.append(0x91000013)              # mov x19, x0
    ins.append(0xF100029F)              # cmp x19, #0

    # 无论成败都 dump 结构体，再走退出
    idx_after = len(ins)
    ins.append(0xD2800020)              # movz x0, #1
    ins.append(add_imm(1, 31, base_off))
    load_const(ins, 2, ssize, True)     # movz x2, #ssize
    ins.append(0xD2800808)              # movz x8, #64 (write)
    ins.append(SVC)
    ins.append(0x91000260)              # mov x0, x19
    ins.append(0xD2800BA8)              # movz x8, #93
    ins.append(SVC)

    idx_exit_open = len(ins)
    ins.append(0x910002A0)              # mov x0, x21
    ins.append(0xD2800BA8)
    ins.append(SVC)

    ins[b_open] = 0x54000000 | (((idx_exit_open - b_open) & 0x7FFFF) << 5) | 4
    return b"".join(struct.pack("<I", i) for i in ins)


def elf(code):
    BASE = 0x400000
    EH, PH = 64, 56
    off = EH + PH
    total = off + len(code)
    e_ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    ehdr = struct.pack("<16sHHIQQQIHHHHHH", e_ident, 2, 183, 1,
                       BASE + off, EH, 0, 0, EH, PH, 1, 64, 0, 0)
    phdr = struct.pack("<IIQQQQQQ", 1, 5, 0, BASE, BASE, total, total, 0x1000)
    return ehdr + phdr + code


if __name__ == "__main__":
    if len(sys.argv) < 5:
        print(__doc__)
        sys.exit(1)
    out = sys.argv[1]
    req = int(sys.argv[2], 0)
    ssize = int(sys.argv[3], 0)
    spec = sys.argv[4]

    fields = []
    for item in spec.split(","):
        item = item.strip()
        if not item:
            continue
        o, v, w = item.split(":")
        fields.append((int(o, 0), (v if v.strip().lower() == "sp" else int(v, 0)), int(w, 0)))

    code = build(req, ssize, fields)
    blob = elf(code)
    open(out, "wb").write(blob)
    print(f"[+] {out}: {len(blob)} bytes, {len(code)//4} insns, "
          f"req=0x{req:08X}, struct={ssize}B, fields={fields}")
