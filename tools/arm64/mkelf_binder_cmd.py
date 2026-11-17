#!/usr/bin/env python3
"""
mkelf_binder_cmd.py — 通用 binder ioctl 探测器

对一个给定的 binder ioctl 命令值，打开 /dev/binder 调用一次并回传返回值。
同时支持扫描模式：扫 nr 1..N，size 固定，找出哪些 nr 被内核认识。

用法：
    # 单发
    python mkelf_binder_cmd.py b1 0x40046205 4
    # 扫 nr（size 固定 48）
    python mkelf_binder_cmd.py bscan 0xC0306201 48 --scan 1 32
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

def str64(rt, rn, off):
    return 0xF9000000 | (((off // 8) & 0xFFF) << 10) | ((rn & 0x1F) << 5) | (rt & 0x1F)

def strb(rt, rn, off):
    return 0x39000000 | ((off & 0xFFF) << 10) | ((rn & 0x1F) << 5) | (rt & 0x1F)

def bcond(cond, off_bytes):
    return 0x54000000 | (((off_bytes // 4) & 0x7FFFF) << 5) | (cond & 0xF)

SVC = 0xD4000001
NE = 1
MI = 4

PATH_OFF, STAT_OFF, BUF_OFF = 0, 32, 64
FRAME = 256


def build(req, scan=None):
    path = b"/dev/binder\x00".ljust(24, b"\x00")
    p0, p1, p2 = (struct.unpack("<Q", path[i:i+8])[0] for i in (0, 8, 16))

    ins = []
    ins.append(0xD1000000 | ((FRAME & 0xFFF) << 10) | (31 << 5) | 31)

    ins.append(movz64(9, p0 & 0xFFFF))
    for sh in (16, 32, 48):
        ins.append(movk64(9, (p0 >> sh) & 0xFFFF, sh))
    ins.append(movz64(10, p1 & 0xFFFF))
    for sh in (16, 32, 48):
        ins.append(movk64(10, (p1 >> sh) & 0xFFFF, sh))
    ins.append(stp(9, 10, 31, 0))
    ins.append(movz64(11, p2 & 0xFFFF))
    for sh in (16, 32, 48):
        ins.append(movk64(11, (p2 >> sh) & 0xFFFF, sh))
    ins.append(str64(11, 31, 16))

    for off in range(32, FRAME, 16):
        ins.append(stp(31, 31, 31, off))

    ins.append(0x92800C60)
    ins.append(add_imm(1, 31, PATH_OFF))
    ins.append(0xD2800042)
    ins.append(0xD2800708)
    ins.append(SVC)
    ins.append(0x91000015)
    ins.append(0xF100001F)
    b_open = len(ins); ins.append(0)

    if scan is None:
        # 单发：x1 = req 常量
        ins.append(movz32(1, req & 0xFFFF))
        for sh in (16,):
            if (req >> sh) & 0xFFFF:
                ins.append(movk32(1, (req >> sh) & 0xFFFF, sh))
        ins.append(0x910002A0)
        ins.append(add_imm(2, 31, BUF_OFF))
        ins.append(0xD28003A8)
        ins.append(SVC)
        ins.append(strb(0, 31, STAT_OFF))
        ins.append(0xD2800020)
        ins.append(add_imm(1, 31, STAT_OFF))
        ins.append(0xD2800022)
        ins.append(0xD2800808)
        ins.append(SVC)
    else:
        nr_lo, nr_hi = scan
        # 固定部分：x27 = req & 0xFFFFFF00
        ins.append(movz32(27, req & 0xFFFF))
        if (req >> 16) & 0xFFFF:
            ins.append(movk32(27, (req >> 16) & 0xFFFF, 16))
        ins.append(movz64(25, nr_lo))
        ins.append(movz64(26, nr_hi))
        loop = len(ins)
        ins.append(add_reg32(1, 27, 25))   # w1 = base | nr
        ins.append(0x910002A0)
        ins.append(add_imm(2, 31, BUF_OFF))
        ins.append(0xD28003A8)
        ins.append(SVC)
        ins.append(strb(25, 31, STAT_OFF))
        ins.append(strb(0, 31, STAT_OFF + 1))
        ins.append(0xD2800020)
        ins.append(add_imm(1, 31, STAT_OFF))
        ins.append(0xD2800042)
        ins.append(0xD2800808)
        ins.append(SVC)
        ins.append(add_imm(25, 25, 1))
        ins.append(subs32(25, 26))
        b_loop = len(ins); ins.append(0)

    end = len(ins)
    ins.append(0xD2800000)
    ins.append(0xD2800BA8)
    ins.append(SVC)

    fail = len(ins)
    ins.append(0x910002A0)
    ins.append(0xD2800BA8)
    ins.append(SVC)

    ins[b_open] = bcond(MI, (fail - b_open) * 4)
    if scan is not None:
        ins[b_loop] = bcond(NE, (loop - b_loop) * 4)
    return b"".join(struct.pack("<I", i) for i in ins)


def elf(cb):
    BASE = 0x400000
    EH, PH = 64, 56
    off = EH + PH
    total = off + len(cb)
    e_ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    ehdr = struct.pack("<16sHHIQQQIHHHHHH", e_ident, 2, 183, 1,
                       BASE + off, EH, 0, 0, EH, PH, 1, 64, 0, 0)
    phdr = struct.pack("<IIQQQQQQ", 1, 5, 0, BASE, BASE, total, total, 0x1000)
    return ehdr + phdr + cb


if __name__ == "__main__":
    out = sys.argv[1]
    req = int(sys.argv[2], 0)
    scan = None
    if "--scan" in sys.argv:
        i = sys.argv.index("--scan")
        scan = (int(sys.argv[i+1], 0), int(sys.argv[i+2], 0))
    cb = build(req, scan)
    open(out, "wb").write(elf(cb))
    print(f"[+] {out}: {len(cb)+120} bytes, req=0x{req:08X}, scan={scan}")
