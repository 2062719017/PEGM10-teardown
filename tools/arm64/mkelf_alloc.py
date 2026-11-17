#!/usr/bin/env python3
"""
mkelf_alloc.py — 生成 ARM64 静态 ELF：从 adb shell 合法调用
KGSL_GPUMEM_ALLOC_ID，申请 1 MB GPU 内存，并把内核回填的结构体写到 stdout。

等效 C：

    int fd = open("/dev/kgsl-3d0", O_RDWR);
    if (fd < 0) exit(fd);
    struct kgsl_gpumem_alloc_id a = {0};
    a.size  = 0x100000;          // 1 MB
    a.flags = 0;
    int rc = ioctl(fd, _IOWR(0x09, 0x34, struct kgsl_gpumem_alloc_id), &a);
    write(1, &a, sizeof(a));
    exit(rc);

struct kgsl_gpumem_alloc_id 布局（LP64，共 32 字节）：
    +0   u32 id
    +4   u32 flags
    +8   u64 size
    +16  u64 mmapsize
    +24  u64 gpuaddr

栈布局（sub sp, #96）：
    [sp+ 0 .. 15]  路径
    [sp+32 .. 63]  ioctl 参数/输出结构体

成功时 rc=0，结构体里 id / mmapsize / gpuaddr 会被内核填上。
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

def sub_sp(imm12):
    return 0xD1000000 | ((imm12 & 0xFFF) << 10) | (31 << 5) | 31

def stp(rt, rt2, rn, off):
    return 0xA9000000 | (((off // 8) & 0x7F) << 15) | ((rt2 & 0x1F) << 10) | ((rn & 0x1F) << 5) | (rt & 0x1F)

def str_imm(rt, rn, off):
    return 0xF9000000 | (((off // 8) & 0xFFF) << 10) | ((rn & 0x1F) << 5) | (rt & 0x1F)


def build(req=0xC0200934, size=0x100000, flags=0, out_off=32):
    path = b"/dev/kgsl-3d0\x00".ljust(16, b"\x00")
    lo = struct.unpack("<Q", path[0:8])[0]
    hi = struct.unpack("<Q", path[8:16])[0]

    ins = []
    ins.append(sub_sp(96))
    ins.append(movz64(9, lo & 0xFFFF))
    ins.append(movk64(9, (lo >> 16) & 0xFFFF, 16))
    ins.append(movk64(9, (lo >> 32) & 0xFFFF, 32))
    ins.append(movk64(9, (lo >> 48) & 0xFFFF, 48))
    ins.append(movz64(10, hi & 0xFFFF))
    ins.append(movk64(10, (hi >> 16) & 0xFFFF, 16))
    ins.append(movk64(10, (hi >> 32) & 0xFFFF, 32))
    ins.append(movk64(10, (hi >> 48) & 0xFFFF, 48))
    ins.append(stp(9, 10, 31, 0))               # stp x9, x10, [sp]
    ins.append(0x92800C60)                      # movn x0, #99   (AT_FDCWD)
    ins.append(add_imm(1, 31, 0))               # mov x1, sp
    ins.append(0xD2800042)                      # movz x2, #2    (O_RDWR)
    ins.append(0xD2800708)                      # movz x8, #56   (openat)
    ins.append(0xD4000001)                      # svc #0
    ins.append(0x91000013)                      # mov x19, x0
    ins.append(0xF100001F)                      # cmp x0, #0
    idx_bmi = len(ins)
    ins.append(0)                               # b.mi FAIL

    # 清空结构体：id/flags(+0)、mmapsize(+16)、gpuaddr(+24)
    ins.append(stp(31, 31, 31, out_off))        # stp xzr, xzr, [sp, #32]
    ins.append(str_imm(31, 31, out_off + 16))   # str xzr, [sp, #48]
    ins.append(str_imm(31, 31, out_off + 24))   # str xzr, [sp, #56]
    # size 字段 (+8)
    if size:
        lo16 = size & 0xFFFF
        if lo16:
            ins.append(movz64(9, lo16))
        else:
            ins.append(movz64(9, 0))
        for sh in (16, 32, 48):
            part = (size >> sh) & 0xFFFF
            if part:
                ins.append(movk64(9, part, sh))
        ins.append(str_imm(9, 31, out_off + 8))
    if flags:
        ins.append(movz64(9, flags & 0xFFFF))
        ins.append(str_imm(9, 31, out_off))     # 覆盖 +0 的 flags 低 4 字节
    # 若 flags 为 0，则用上面的 stp xzr 归零

    # ioctl
    ins.append(0x91000260)                      # mov x0, x19
    ins.append(movz32(1, req & 0xFFFF))
    ins.append(movk32(1, (req >> 16) & 0xFFFF, 16))
    ins.append(add_imm(2, 31, out_off))         # add x2, sp, #32
    ins.append(0xD28003A8)                      # movz x8, #29   (ioctl)
    ins.append(0xD4000001)                      # svc #0
    ins.append(0x91000013)                      # mov x19, x0

    # write(1, sp+out_off, 32)
    ins.append(0xD2800020)                      # movz x0, #1
    ins.append(add_imm(1, 31, out_off))         # add x1, sp, #32
    ins.append(0xD2800402)                      # movz x2, #32
    ins.append(0xD2800808)                      # movz x8, #64   (write)
    ins.append(0xD4000001)                      # svc #0

    # exit(rc)
    ins.append(0x91000260)
    ins.append(0xD2800BA8)
    ins.append(0xD4000001)

    idx_fail = len(ins)
    ins.append(0x91000260)
    ins.append(0xD2800BA8)
    ins.append(0xD4000001)

    imm19 = (idx_fail - idx_bmi) & 0x7FFFF
    ins[idx_bmi] = 0x54000000 | (imm19 << 5) | 4
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
    out = sys.argv[1] if len(sys.argv) > 1 else "kgslalloc"
    req = int(sys.argv[2], 0) if len(sys.argv) > 2 else 0xC0200934
    size = int(sys.argv[3], 0) if len(sys.argv) > 3 else 0x100000
    flags = int(sys.argv[4], 0) if len(sys.argv) > 4 else 0
    code = build(req, size, flags)
    blob = elf(code)
    open(out, "wb").write(blob)
    print(f"[+] {out}: {len(blob)} bytes, {len(code)//4} insns, req=0x{req:08X}, "
          f"size=0x{size:x}, flags=0x{flags:x}")
