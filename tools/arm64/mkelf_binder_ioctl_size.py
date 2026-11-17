#!/usr/bin/env python3
"""
mkelf_binder_ioctl_size.py — 探测内核 binder_write_read 结构体的真实大小

binder 驱动的 ioctl 用 switch(cmd) 精确匹配，cmd 里的 size 字段必须等于
内核里 sizeof(struct binder_write_read)，否则落到 default 分支返回 -EINVAL。

本工具对 size = 8..128 逐个构造 cmd = _IOWR('b', 1, size)，
配合一条无害的 BC_ENTER_LOOPER(0x0c) 命令，找出哪个 size 不返回 EINVAL。

每个 size 输出 2 字节：[size, 返回值低字节]
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

def stp(rt, rt2, rn, off):
    return 0xA9000000 | (((off // 8) & 0x7F) << 15) | ((rt2 & 0x1F) << 10) | ((rn & 0x1F) << 5) | (rt & 0x1F)

def str32(rt, rn, off):
    return 0xB9000000 | (((off // 4) & 0xFFF) << 10) | ((rn & 0x1F) << 5) | (rt & 0x1F)

def str64(rt, rn, off):
    return 0xF9000000 | (((off // 8) & 0xFFF) << 10) | ((rn & 0x1F) << 5) | (rt & 0x1F)

def strb(rt, rn, off):
    return 0x39000000 | ((off & 0xFFF) << 10) | ((rn & 0x1F) << 5) | (rt & 0x1F)

def lsl32(rd, rn, sh):
    immr = (32 - sh) % 32
    imms = 31 - sh
    return 0x53000000 | ((immr & 0x3F) << 16) | ((imms & 0x3F) << 10) | ((rn & 0x1F) << 5) | (rd & 0x1F)

def add_reg32(rd, rn, rm):
    return 0x0B000000 | ((rm & 0x1F) << 16) | ((rn & 0x1F) << 5) | (rd & 0x1F)

def bcond(cond, off_bytes):
    return 0x54000000 | (((off_bytes // 4) & 0x7FFFF) << 5) | (cond & 0xF)

SVC = 0xD4000001
NE = 1
MI = 4

PATH_OFF = 0
STAT_OFF = 32
BWR_OFF = 64
WBUF_OFF = 256
FRAME = 320


def build(smin=8, smax=128):
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

    # open
    ins.append(0x92800C60)
    ins.append(add_imm(1, 31, PATH_OFF))
    ins.append(0xD2800042)
    ins.append(0xD2800708)
    ins.append(SVC)
    ins.append(0x91000015)
    ins.append(0xF100001F)
    b_open = len(ins); ins.append(0)

    # 固定 bwr：write_size=4, write_buffer=sp+WBUF_OFF，其余 0
    ins.append(movz64(9, 4))
    ins.append(str64(9, 31, BWR_OFF + 0))
    ins.append(add_imm(9, 31, WBUF_OFF))
    ins.append(str64(9, 31, BWR_OFF + 16))

    # 写缓冲内容：BC_ENTER_LOOPER = 0x0c
    ins.append(movz32(9, 0x0C))
    ins.append(str32(9, 31, WBUF_OFF))

    ins.append(movz64(25, smin))          # size 计数
    ins.append(movz64(26, smax))

    loop = len(ins)
    # cmd = 0xC0000000 | (size << 16) | 0x6201
    # 高 16 位 = (dir<<14) | size = 0xC000 | size（size < 0x4000）
    ins.append(movz32(1, 0x6201))         # w1 = 0x6201
    ins.append(movz32(2, 0xC000))         # w2 = 0xC000
    ins.append(add_reg32(2, 2, 25))       # w2 = 0xC000 + size
    # ORR w1, w1, w2, LSL #16   -> 0x2A000000 | (16<<22) | (Rm<<16) | (Rn<<5) | Rd
    ins.append(0x2A000000 | (16 << 22) | (2 << 16) | (1 << 5) | 1)

    ins.append(0x910002A0)                # mov x0, x21
    ins.append(add_imm(2, 31, BWR_OFF))   # mov x2, sp+BWR_OFF
    ins.append(0xD28003A8)                # movz x8, #29
    ins.append(SVC)
    ins.append(strb(25, 31, STAT_OFF + 0))  # [0] = size
    ins.append(strb(0, 31, STAT_OFF + 1))   # [1] = rc
    ins.append(0xD2800020)
    ins.append(add_imm(1, 31, STAT_OFF))
    ins.append(0xD2800042)                  # 2 bytes
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
    out = sys.argv[1] if len(sys.argv) > 1 else "bsize"
    cb = build()
    open(out, "wb").write(elf(cb))
    print(f"[+] {out}: {len(cb)+120} bytes, {len(cb)//4} insns")
