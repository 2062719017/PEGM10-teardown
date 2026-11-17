#!/usr/bin/env python3
"""
mkelf_scan.py — KGSL ioctl 表枚举器（ARM64 静态 ELF，零编译依赖）

对 /dev/kgsl-3d0 依次发起 nr = 1 .. 0x5F 的 ioctl，
统一用 _IOWR(0x09, nr, 32) 作为请求号，参数为指向 32 字节零缓冲的指针。

每个 nr 向 stdout 输出 2 字节原始记录：
    [0] = nr
    [1] = 返回值低 8 位（0 表示调用成功；256-值 = errno）

判读规则：
    ENOTTY(25) -> 0xE7 该 nr 未注册
    EINVAL(22) -> 0xEA 已注册但参数/结构不符（或处理器内部拒绝）
    EFAULT(14) -> 0xF2 已注册且进入 copy_from_user
    0          -> 0x00 调用成功

用法：
    python mkelf_scan.py kgslscan
    adb push kgslscan /data/local/tmp/ && adb shell 'chmod 755 /data/local/tmp/kgslscan; /data/local/tmp/kgslscan' > scan.bin
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

def add_reg32(rd, rn, rm):
    return 0x0B000000 | ((rm & 0x1F) << 16) | ((rn & 0x1F) << 5) | (rd & 0x1F)

def subs32(rn, rm):
    return 0xEB000000 | ((rm & 0x1F) << 16) | ((rn & 0x1F) << 5) | 31

def stp(rt, rt2, rn, off):
    return 0xA9000000 | (((off // 8) & 0x7F) << 15) | ((rt2 & 0x1F) << 10) | ((rn & 0x1F) << 5) | (rt & 0x1F)

def strb(rt, rn, off):
    return 0x39000000 | ((off & 0xFFF) << 10) | ((rn & 0x1F) << 5) | (rt & 0x1F)

def bcond(cond, off_bytes):
    imm19 = (off_bytes // 4) & 0x7FFFF
    return 0x54000000 | (imm19 << 5) | (cond & 0xF)

SVC = 0xD4000001
NE = 1
MI = 4


def build(start=1, end=0x60, base_off=32):
    path = b"/dev/kgsl-3d0\x00".ljust(16, b"\x00")
    lo = struct.unpack("<Q", path[0:8])[0]
    hi = struct.unpack("<Q", path[8:16])[0]

    ins = []
    ins.append(0xD10203FF)                  # sub sp, sp, #128
    ins.append(movz64(9, lo & 0xFFFF))
    for sh in (16, 32, 48):
        ins.append(movk64(9, (lo >> sh) & 0xFFFF, sh))
    ins.append(movz64(10, hi & 0xFFFF))
    for sh in (16, 32, 48):
        ins.append(movk64(10, (hi >> sh) & 0xFFFF, sh))
    ins.append(stp(9, 10, 31, 0))

    ins.append(0x92800C60)                  # movn x0, #99
    ins.append(add_imm(1, 31, 0))           # mov x1, sp
    ins.append(0xD2800042)                  # movz x2, #2
    ins.append(0xD2800708)                  # movz x8, #56
    ins.append(SVC)
    ins.append(0x91000015)                  # mov x21, x0
    ins.append(0xF100001F)                  # cmp x0, #0
    b_open = len(ins); ins.append(0)

    ins.append(movz64(22, start))           # x22 = nr 计数
    ins.append(movz64(23, end))             # x23 = 结束值

    loop_idx = len(ins)
    ins.append(movz32(1, 0x0900))           # movz w1, #0x0900
    ins.append(movk32(1, 0xC020, 16))       # movk w1, #0xC020, lsl 16
    ins.append(add_reg32(1, 1, 22))         # add w1, w1, w22
    ins.append(0x910002A0)                  # mov x0, x21
    ins.append(add_imm(2, 31, base_off))    # add x2, sp, #32
    ins.append(0xD28003A8)                  # movz x8, #29
    ins.append(SVC)
    ins.append(strb(22, 31, 16))            # strb w22, [sp, #16]   nr
    ins.append(strb(0, 31, 17))             # strb w0,  [sp, #17]   返回值低字节
    ins.append(0xD2800020)                  # movz x0, #1
    ins.append(add_imm(1, 31, 16))          # add x1, sp, #16
    ins.append(0xD2800042)                  # movz x2, #2
    ins.append(0xD2800808)                  # movz x8, #64
    ins.append(SVC)
    ins.append(add_imm(22, 22, 1))          # add x22, x22, #1
    ins.append(subs32(22, 23))              # cmp x22, x23
    b_loop = len(ins); ins.append(0)

    ins.append(0xD2800000)                  # movz x0, #0
    ins.append(0xD2800BA8)                  # movz x8, #93
    ins.append(SVC)

    idx_fail = len(ins)
    ins.append(0x910002A0)
    ins.append(0xD2800BA8)
    ins.append(SVC)

    ins[b_open] = bcond(MI, (idx_fail - b_open) * 4)
    ins[b_loop] = bcond(NE, (loop_idx - b_loop) * 4)
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
    out = sys.argv[1] if len(sys.argv) > 1 else "kgslscan"
    code = build()
    blob = elf(code)
    open(out, "wb").write(blob)
    print(f"[+] {out}: {len(blob)} bytes, {len(code)//4} insns")
