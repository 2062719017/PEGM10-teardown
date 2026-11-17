#!/usr/bin/env python3
"""
mkelf_binder.py — binder 驱动可达性探测（ARM64 静态 ELF，零编译依赖）

流程：
    fd  = open(path, O_RDWR)
    ioctl(fd, BINDER_VERSION, &ver)          # 读协议版本
    ioctl(fd, BINDER_WRITE_READ, &bwr)       # 全零结构，测写读入口
    p   = mmap(NULL, 131072, RW, MAP_PRIVATE, fd, 0)   # binder 缓冲区
    write(1, out, 6)

输出 6 字节：
    [0] open 成功 ? 1 : 0
    [1] BINDER_VERSION 低字节（正常应为 8）
    [2] BINDER_WRITE_READ 返回值低字节
    [3] mmap 成功 ? 1 : 0
    [4] mmap 返回/errno 低字节（256-值 = errno）
    [5] 保留 0

binder ioctl（uapi/linux/android/binder.h）：
    BINDER_WRITE_READ  _IOWR('b', 1, struct binder_write_read) = 0xC0306201 (48B)
    BINDER_VERSION     _IOWR('b', 9, struct binder_version)    = 0xC0046209 (4B)
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

def strb(rt, rn, off):
    return 0x39000000 | ((off & 0xFFF) << 10) | ((rn & 0x1F) << 5) | (rt & 0x1F)

def ldr32(rt, rn, off):
    return 0xB9400000 | (((off // 4) & 0xFFF) << 10) | ((rn & 0x1F) << 5) | (rt & 0x1F)

SVC = 0xD4000001


def load_const(ins, reg, value, wide=True):
    """把任意 64 位/32 位立即数正确装载进寄存器（movz + movk 链）"""
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


def build(path_str, map_size=1040384, prot=1, mflags=0x4002):
    path = path_str.encode().ljust(24, b"\x00")
    p0 = struct.unpack("<Q", path[0:8])[0]
    p1 = struct.unpack("<Q", path[8:16])[0]
    p2 = struct.unpack("<Q", path[16:24])[0]

    ins = []
    ins.append(0xD10203FF)                       # sub sp, sp, #128

    # 路径 -> [sp+0..23]
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

    # 结果区清零 [sp+32..47]，以及 BINDER_WRITE_READ 结构体 [sp+48..95]
    ins.append(stp(31, 31, 31, 32))
    ins.append(stp(31, 31, 31, 48))
    ins.append(stp(31, 31, 31, 64))
    ins.append(stp(31, 31, 31, 80))

    # openat(AT_FDCWD, sp, O_RDWR)
    ins.append(0x92800C60)                       # movn x0, #99
    ins.append(add_imm(1, 31, 0))                # mov x1, sp
    ins.append(0xD2800042)                       # movz x2, #2
    ins.append(0xD2800708)                       # movz x8, #56
    ins.append(SVC)
    ins.append(0x91000015)                       # mov x21, x0
    ins.append(0xF100001F)                       # cmp x0, #0
    b_open = len(ins); ins.append(0)
    ins.append(0xD2800029)                       # movz w9, #1
    ins.append(strb(9, 31, 32))                  # [32] = 1

    # BINDER_VERSION -> [sp+96]
    ins.append(0x910002A0)                       # mov x0, x21
    ins.append(movz32(1, 0x6209))
    ins.append(movk32(1, 0xC004, 16))
    ins.append(add_imm(2, 31, 96))
    ins.append(0xD28003A8)                       # movz x8, #29
    ins.append(SVC)
    ins.append(ldr32(0, 31, 96))                 # ldr w0, [sp, #96]
    ins.append(strb(0, 31, 33))                  # [33] = 版本

    # BINDER_WRITE_READ（全零结构 [sp+48]）
    ins.append(0x910002A0)
    ins.append(movz32(1, 0x6201))
    ins.append(movk32(1, 0xC030, 16))
    ins.append(add_imm(2, 31, 48))
    ins.append(0xD28003A8)
    ins.append(SVC)
    ins.append(strb(0, 31, 34))                  # [34] = 返回值

    # mmap(NULL, 131072, PROT_READ, MAP_PRIVATE|MAP_NORESERVE, fd, 0)
    # 注意：libbinder 用的是 PROT_READ 而非 PROT_WRITE，写权限映射会被 binder 拒绝(EINVAL)
    ins.append(0xD2800000)                       # movz x0, #0
    load_const(ins, 1, map_size)
    load_const(ins, 2, prot)
    load_const(ins, 3, mflags)
    ins.append(0x910002A4)                       # mov x4, x21
    ins.append(0xD2800005)                       # movz x5, #0
    ins.append(0xD2801BC8)                       # movz x8, #222
    ins.append(SVC)
    ins.append(0x91000014)                       # mov x20, x0   （结果或 -errno）
    ins.append(0xAA1403E9)                       # mov x9, x20
    ins.append(strb(9, 31, 36))                  # [36] = 低字节
    ins.append(0xF100029F)                       # cmp x20, #0
    b_mm = len(ins); ins.append(0)
    ins.append(0xD2800029)                       # movz w9, #1
    ins.append(strb(9, 31, 35))                  # [35] = 1  (成功)

    # 统一输出 6 字节
    end = len(ins)
    ins.append(0xD2800020)                       # movz x0, #1
    ins.append(add_imm(1, 31, 32))
    ins.append(0xD28000C2)                       # movz x2, #6
    ins.append(0xD2800808)                       # movz x8, #64
    ins.append(SVC)
    ins.append(0xD2800000)                       # exit 0
    ins.append(0xD2800BA8)
    ins.append(SVC)

    fail = len(ins)
    ins.append(0xD2800020)
    ins.append(add_imm(1, 31, 32))
    ins.append(0xD28000C2)
    ins.append(0xD2800808)
    ins.append(SVC)
    ins.append(0x910002A0)                       # exit(errno)
    ins.append(0xD2800BA8)
    ins.append(SVC)

    ins[b_open] = 0x54000000 | (((fail - b_open) & 0x7FFFF) << 5) | 4
    ins[b_mm] = 0x54000000 | (((end - b_mm) & 0x7FFFF) << 5) | 4
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
    path = sys.argv[1] if len(sys.argv) > 1 else "/dev/binder"
    out = sys.argv[2] if len(sys.argv) > 2 else "binderprobe"
    msize = int(sys.argv[3], 0) if len(sys.argv) > 3 else 131072
    prot = int(sys.argv[4], 0) if len(sys.argv) > 4 else 1
    mflags = int(sys.argv[5], 0) if len(sys.argv) > 5 else 0x4002
    code = build(path, msize, prot, mflags)
    blob = elf(code)
    open(out, "wb").write(blob)
    print(f"[+] {out}: {len(blob)} bytes, path={path}, size=0x{msize:x}, "
          f"prot={prot}, flags=0x{mflags:x}")
