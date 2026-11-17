#!/usr/bin/env python3
"""
mkelf_ctx.py — DRAWCTXT_CREATE 的 context type 穷举器

对 KGSL_DRAWCTXT_CREATE(0x13) 依次尝试 flags = type << 20，type 从 0 到 31，
覆盖 KGSL_CONTEXT_TYPE_MASK(0x01F00000) 的全部取值。

每个 type 向 stdout 输出 2 字节：
    [0] = type
    [1] = 返回值低 8 位（0 = 成功；否则 256-值 = errno）

用法：
    python mkelf_ctx.py kgslctx
    adb push kgslctx /data/local/tmp/ && adb shell 'chmod 755 /data/local/tmp/kgslctx; /data/local/tmp/kgslctx > /data/local/tmp/ctx.bin'
    adb pull /data/local/tmp/ctx.bin
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

def subs32(rn, rm):
    return 0xEB000000 | ((rm & 0x1F) << 16) | ((rn & 0x1F) << 5) | 31

def lsl32(rd, rn, sh):
    immr = (32 - sh) % 32
    imms = 31 - sh
    return 0x53000000 | ((immr & 0x3F) << 16) | ((imms & 0x3F) << 10) | ((rn & 0x1F) << 5) | (rd & 0x1F)

def stp(rt, rt2, rn, off):
    return 0xA9000000 | (((off // 8) & 0x7F) << 15) | ((rt2 & 0x1F) << 10) | ((rn & 0x1F) << 5) | (rt & 0x1F)

def str32(rt, rn, off):
    return 0xB9000000 | (((off // 4) & 0xFFF) << 10) | ((rn & 0x1F) << 5) | (rt & 0x1F)

def strb(rt, rn, off):
    return 0x39000000 | ((off & 0xFFF) << 10) | ((rn & 0x1F) << 5) | (rt & 0x1F)

def bcond(cond, off_bytes):
    return 0x54000000 | ((((off_bytes // 4) & 0x7FFFF)) << 5) | (cond & 0xF)

SVC = 0xD4000001
NE = 1
MI = 4


def build(count=32, base_off=32):
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
    ins.append(add_imm(1, 31, 0))
    ins.append(0xD2800042)                  # movz x2, #2
    ins.append(0xD2800708)                  # movz x8, #56
    ins.append(SVC)
    ins.append(0x91000015)                  # mov x21, x0
    ins.append(0xF100001F)                  # cmp x0, #0
    b_open = len(ins); ins.append(0)

    ins.append(movz64(25, 0))               # x25 = type 计数
    ins.append(movz64(26, count))           # x26 = 结束

    loop = len(ins)
    ins.append(stp(31, 31, 31, base_off))   # 清零结构体前 16 字节
    ins.append(lsl32(1, 25, 20))            # lsl w1, w25, #20   -> flags = type << 20
    ins.append(str32(1, 31, base_off))      # str w1, [sp, #32]  struct.flags
    ins.append(0x910002A0)                  # mov x0, x21        fd
    ins.append(movz32(1, 0x0913))           # movz w1, #0x0913
    ins.append(movk32(1, 0xC008, 16))       # movk w1, #0xC008, lsl 16  -> _IOWR(0x09,0x13,8)
    ins.append(add_imm(2, 31, base_off))    # add x2, sp, #32
    ins.append(0xD28003A8)                  # movz x8, #29
    ins.append(SVC)
    ins.append(strb(25, 31, 16))            # strb w25, [sp, #16]  type
    ins.append(strb(0, 31, 17))             # strb w0,  [sp, #17]  rc
    ins.append(0xD2800020)                  # movz x0, #1
    ins.append(add_imm(1, 31, 16))
    ins.append(0xD2800042)                  # movz x2, #2
    ins.append(0xD2800808)                  # movz x8, #64
    ins.append(SVC)
    ins.append(add_imm(25, 25, 1))          # add x25, x25, #1
    ins.append(subs32(25, 26))              # cmp x25, x26
    b_loop = len(ins); ins.append(0)

    ins.append(0xD2800000)
    ins.append(0xD2800BA8)
    ins.append(SVC)

    fail = len(ins)
    ins.append(0x910002A0)
    ins.append(0xD2800BA8)
    ins.append(SVC)

    ins[b_open] = bcond(MI, (fail - b_open) * 4)
    ins[b_loop] = bcond(NE, (loop - b_loop) * 4)
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
    out = sys.argv[1] if len(sys.argv) > 1 else "kgslctx"
    code = build()
    blob = elf(code)
    open(out, "wb").write(blob)
    print(f"[+] {out}: {len(blob)} bytes, {len(code)//4} insns")
