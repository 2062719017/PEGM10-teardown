#!/usr/bin/env python3
"""
mkelf_chain.py — ARM64 静态 ELF：单进程内跑通 kgsl 堆原语全链

    fd = open("/dev/kgsl-3d0", O_RDWR)
    a  = { .size = 0x100000 };                       // +8
    ioctl(fd, _IOWR(0x09,0x34,32), &a);              // GPUMEM_ALLOC_ID
    gi = { .id = a.id };                             // +8
    ioctl(fd, _IOWR(0x09,0x36,32), &gi);             // GPUMEM_GET_INFO
    p  = mmap(NULL, gi.size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, gi.mmap_offset);
    write(1, p, 16);                                 // 证明 CPU 可读
    exit(0)

关键点：kgsl 对象随 fd 关闭而释放，三段 ioctl 必须在同一进程同一 fd 上连续完成。

栈布局（sub sp, #128）：
    [sp+ 0.. 15]  路径
    [sp+32.. 63]  alloc 结构体    +0 id  +4 flags  +8 size  +16 mmapsize  +24 gpuaddr
    [sp+64.. 95]  get_info 结构体 +0 gpuaddr  +8 id  +12 flags  +16 size  +24 mmap_offset
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

def ldr64(rt, rn, off):
    return 0xF9400000 | (((off // 8) & 0xFFF) << 10) | ((rn & 0x1F) << 5) | (rt & 0x1F)

def ldr32(rt, rn, off):
    return 0xB9400000 | (((off // 4) & 0xFFF) << 10) | ((rn & 0x1F) << 5) | (rt & 0x1F)

def str64(rt, rn, off):
    return 0xF9000000 | (((off // 8) & 0xFFF) << 10) | ((rn & 0x1F) << 5) | (rt & 0x1F)

SVC = 0xD4000001
CMP_X19_0 = 0xF100029F

# 阶段标记：把字符写到 [sp+16] 再 write(1) 出来
def marker(ins, ch):
    ins.append(movz64(9, ch))                 # movz x9, #char
    ins.append(0x390043E9)                    # strb w9, [sp, #16]
    ins.append(0xD2800020)                    # movz x0, #1
    ins.append(0x910043E1)                    # add x1, sp, #16
    ins.append(0xD2800022)                    # movz x2, #1
    ins.append(0xD2800808)                    # movz x8, #64
    ins.append(SVC)


def build(size=0x100000, alloc_off=32, gi_off=64):
    path = b"/dev/kgsl-3d0\x00".ljust(16, b"\x00")
    lo = struct.unpack("<Q", path[0:8])[0]
    hi = struct.unpack("<Q", path[8:16])[0]

    ins = []
    ins.append(0xD10203FF)                    # sub sp, sp, #128
    ins.append(movz64(9, lo & 0xFFFF))
    ins.append(movk64(9, (lo >> 16) & 0xFFFF, 16))
    ins.append(movk64(9, (lo >> 32) & 0xFFFF, 32))
    ins.append(movk64(9, (lo >> 48) & 0xFFFF, 48))
    ins.append(movz64(10, hi & 0xFFFF))
    ins.append(movk64(10, (hi >> 16) & 0xFFFF, 16))
    ins.append(movk64(10, (hi >> 32) & 0xFFFF, 32))
    ins.append(movk64(10, (hi >> 48) & 0xFFFF, 48))
    ins.append(0xA9002BE9)                    # stp x9, x10, [sp]
    ins.append(0x92800C60)                    # movn x0, #99  (AT_FDCWD)
    ins.append(0x910003E1)                    # mov x1, sp
    ins.append(0xD2800042)                    # movz x2, #2   (O_RDWR)
    ins.append(0xD2800708)                    # movz x8, #56  (openat)
    ins.append(SVC)
    ins.append(0x91000015)                    # mov x21, x0   (fd)
    ins.append(0xF100001F)                    # cmp x0, #0
    b_open = len(ins); ins.append(0)
    marker(ins, ord('A'))                     # open 成功

    # ---- ALLOC ----
    ins.append(0xA9027FFF)                    # stp xzr, xzr, [sp, #32]
    ins.append(str64(31, 31, alloc_off + 16)) # str xzr, [sp, #48]
    ins.append(str64(31, 31, alloc_off + 24)) # str xzr, [sp, #56]
    # size = 0x100000  ->  movz x9, #0x10, lsl #16
    ins.append(0xD2A00209)
    ins.append(str64(9, 31, alloc_off + 8))   # str x9, [sp, #40]
    ins.append(0x910002A0)                    # mov x0, x21
    ins.append(movz32(1, 0x0934))
    ins.append(movk32(1, 0xC020, 16))
    ins.append(add_imm(2, 31, alloc_off))     # add x2, sp, #32
    ins.append(0xD28003A8)                    # movz x8, #29 (ioctl)
    ins.append(SVC)
    ins.append(0x91000013)                    # mov x19, x0
    ins.append(CMP_X19_0)
    b_alloc = len(ins); ins.append(0)
    marker(ins, ord('B'))                     # alloc 成功

    # ---- GET_INFO ----
    ins.append(0xA9047FFF)                    # stp xzr, xzr, [sp, #64]
    ins.append(str64(31, 31, gi_off + 16))    # str xzr, [sp, #80]
    ins.append(str64(31, 31, gi_off + 24))    # str xzr, [sp, #88]
    ins.append(ldr32(9, 31, alloc_off))       # ldr w9, [sp, #32]   a.id
    ins.append(str64(9, 31, gi_off + 8))      # str x9, [sp, #72]   gi.id
    ins.append(0x910002A0)                    # mov x0, x21
    ins.append(movz32(1, 0x0936))
    ins.append(movk32(1, 0xC018, 16))
    ins.append(add_imm(2, 31, gi_off))        # add x2, sp, #64
    ins.append(0xD28003A8)
    ins.append(SVC)
    ins.append(0x91000013)
    ins.append(CMP_X19_0)
    b_gi = len(ins); ins.append(0)
    marker(ins, ord('C'))                     # get_info 成功

    # ---- mmap ----
    ins.append(0xD2800000)                    # movz x0, #0
    ins.append(ldr64(1, 31, gi_off + 16))     # ldr x1, [sp, #80]  size
    ins.append(0xD2800062)                    # movz x2, #3  PROT_READ|WRITE
    ins.append(0xD2800023)                    # movz x3, #1  MAP_SHARED
    ins.append(0x910002A4)                    # mov x4, x21  fd
    ins.append(ldr64(5, 31, gi_off + 24))     # ldr x5, [sp, #88]  mmap_offset
    ins.append(0xD2801BC8)                    # movz x8, #222 (mmap)
    ins.append(SVC)
    ins.append(0x91000014)                    # mov x20, x0
    ins.append(0xF100029F)                    # cmp x20, #0
    b_map = len(ins); ins.append(0)

    # ---- write(1, p, 16) ----
    marker(ins, ord('D'))                     # mmap 成功
    ins.append(0xD2800020)                    # movz x0, #1
    ins.append(0x91000281)                    # mov x1, x20
    ins.append(0xD2800202)                    # movz x2, #16
    ins.append(0xD2800808)                    # movz x8, #64 (write)
    ins.append(SVC)
    ins.append(0xD2800000)                    # movz x0, #0
    ins.append(0xD2800BA8)                    # movz x8, #93
    ins.append(SVC)

    idx_exit_rc = len(ins)                    # x19 里有 rc
    ins.append(0x91000260)                    # mov x0, x19
    ins.append(0xD2800BA8)
    ins.append(SVC)

    idx_exit_open = len(ins)                  # x21 里有 open 错误
    ins.append(0x910002A0)                    # mov x0, x21
    ins.append(0xD2800BA8)
    ins.append(SVC)

    idx_exit_map = len(ins)                   # x20 里有 mmap 结果
    ins.append(0x91000280)                    # mov x0, x20
    ins.append(0xD2800BA8)
    ins.append(SVC)

    def bmi(idx, target):
        ins[idx] = 0x54000000 | (((target - idx) & 0x7FFFF) << 5) | 4

    bmi(b_open, idx_exit_open)
    bmi(b_alloc, idx_exit_rc)
    bmi(b_gi, idx_exit_rc)
    bmi(b_map, idx_exit_map)
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
    out = sys.argv[1] if len(sys.argv) > 1 else "kgslchain"
    size = int(sys.argv[2], 0) if len(sys.argv) > 2 else 0x100000
    code = build(size)
    blob = elf(code)
    open(out, "wb").write(blob)
    print(f"[+] {out}: {len(blob)} bytes, {len(code)//4} insns, size=0x{size:x}")
