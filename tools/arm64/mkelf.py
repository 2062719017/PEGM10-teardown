#!/usr/bin/env python3
"""
mkelf.py — 不依赖任何编译器，直接生成 ARM64 (aarch64) 静态 ELF。

用途：在拿不到 NDK / 交叉工具链的环境里，验证 adb shell 能否对
      /dev/kgsl-3d0 发起 ioctl（即 SELinux 是否放行 gpu_device 的 ioctl 权限）。

程序逻辑（AArch64 Linux 系统调用直接调用，不链接 libc）：

    fd = openat(AT_FDCWD, "/dev/kgsl-3d0", O_RDWR);
    if (fd < 0) exit(fd);            // 退出码 = errno（256-|errno|）
    rc = ioctl(fd, 0xC0180902, NULL); // _IOWR(0x09,0x02,struct kgsl_device_getproperty)
    exit(rc);

退出码判读（256 减去实际退出码 = errno）：
    EFAULT(14)  -> 退出码 242  => SELinux 放行，驱动已进入 copy_from_user
    EPERM(1)    -> 退出码 255  => SELinux 拒绝（avc denied）
    EACCES(13)  -> 退出码 243  => SELinux / DAC 拒绝
    EINVAL(22)  -> 退出码 234  => 驱动在解引用前就拒绝了参数（同样说明 ioctl 已放行）
    ENOTTY(25)  -> 退出码 231  => 该请求号不被支持
    0           -> 退出码 0    => 调用成功
"""

import struct
import sys

# ---------------- 指令编码工具 ----------------
def movz64(rd, imm16, shift=0):
    return 0xD2800000 | ((shift // 16) << 21) | ((imm16 & 0xFFFF) << 5) | rd

def movk64(rd, imm16, shift=0):
    return 0xF2800000 | ((shift // 16) << 21) | ((imm16 & 0xFFFF) << 5) | rd

def movz32(rd, imm16, shift=0):
    return 0x52800000 | ((shift // 16) << 21) | ((imm16 & 0xFFFF) << 5) | rd

def movk32(rd, imm16, shift=0):
    return 0x72800000 | ((shift // 16) << 21) | ((imm16 & 0xFFFF) << 5) | rd

SUB_SP_64   = 0xD10103FF   # sub sp, sp, #64
STP_X9_X10  = 0xA9002BE9   # stp x9, x10, [sp]
MOVN_X0_100 = 0x92800C60   # movn x0, #99  -> x0 = -100 (AT_FDCWD)
ADD_X1_SP_0 = 0x910003E1   # mov x1, sp
MOV_X2_0    = 0xD2800002   # movz x2, #0
SVC_0       = 0xD4000001   # svc #0
MOV_X19_X0  = 0x91000013   # mov x19, x0
MOV_X0_X19  = 0x91000260   # mov x0, x19
CMP_X0_0    = 0xF100001F   # cmp x0, #0
MOVZ_X8_56  = 0xD2800708   # movz x8, #56  (openat)
MOVZ_X8_29  = 0xD28003A8   # movz x8, #29  (ioctl)
MOVZ_X8_93  = 0xD2800BA8   # movz x8, #93  (exit)
MOVZ_X2_2   = 0xD2800042   # movz x2, #2   (O_RDWR)

def build_code(req=0xC0180902):
    path = b"/dev/kgsl-3d0\x00"           # 14 字节 + NUL = 15，补齐到 16
    path = path.ljust(16, b"\x00")
    lo = struct.unpack("<Q", path[0:8])[0]
    hi = struct.unpack("<Q", path[8:16])[0]

    ins = []
    ins.append(SUB_SP_64)
    # x9 = 前 8 字节
    ins.append(movz64(9, lo & 0xFFFF))
    ins.append(movk64(9, (lo >> 16) & 0xFFFF, 16))
    ins.append(movk64(9, (lo >> 32) & 0xFFFF, 32))
    ins.append(movk64(9, (lo >> 48) & 0xFFFF, 48))
    # x10 = 后 8 字节
    ins.append(movz64(10, hi & 0xFFFF))
    ins.append(movk64(10, (hi >> 16) & 0xFFFF, 16))
    ins.append(movk64(10, (hi >> 32) & 0xFFFF, 32))
    ins.append(movk64(10, (hi >> 48) & 0xFFFF, 48))
    ins.append(STP_X9_X10)          # 把路径写到 [sp]
    ins.append(MOVN_X0_100)         # AT_FDCWD
    ins.append(ADD_X1_SP_0)         # x1 = 路径
    ins.append(MOVZ_X2_2)           # O_RDWR
    ins.append(MOVZ_X8_56)          # openat
    ins.append(SVC_0)
    ins.append(MOV_X19_X0)          # 保存 fd
    ins.append(CMP_X0_0)
    idx_bmi = len(ins)
    ins.append(0)                   # b.mi FAIL（占位，稍后回填）
    # ioctl(fd, 0xC0180902, NULL)
    ins.append(MOV_X0_X19)
    ins.append(movz32(1, req & 0xFFFF))
    ins.append(movk32(1, (req >> 16) & 0xFFFF, 16))
    ins.append(MOV_X2_0)            # NULL 指针
    ins.append(MOVZ_X8_29)          # ioctl
    ins.append(SVC_0)
    ins.append(MOV_X19_X0)          # 保存返回值
    ins.append(MOV_X0_X19)          # exit(rc)
    ins.append(MOVZ_X8_93)
    ins.append(SVC_0)
    # FAIL:
    idx_fail = len(ins)
    ins.append(MOV_X0_X19)          # exit(fd)  -> 退出码即 errno
    ins.append(MOVZ_X8_93)
    ins.append(SVC_0)

    # 回填 b.mi 的 imm19（以指令为单位）
    off = (idx_fail - idx_bmi) * 4
    imm19 = (off // 4) & 0x7FFFF
    ins[idx_bmi] = 0x54000000 | (imm19 << 5) | 4   # cond = MI (0b0100)

    return b"".join(struct.pack("<I", i) for i in ins), idx_bmi, idx_fail


def build_elf(code):
    BASE = 0x400000
    EHDR_SIZE = 64
    PHDR_SIZE = 56
    code_off = EHDR_SIZE + PHDR_SIZE
    entry = BASE + code_off
    total = code_off + len(code)

    e_ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        e_ident,
        2,            # e_type = ET_EXEC
        183,          # e_machine = EM_AARCH64
        1,            # e_version
        entry,        # e_entry
        EHDR_SIZE,    # e_phoff
        0,            # e_shoff
        0,            # e_flags
        EHDR_SIZE,    # e_ehsize
        PHDR_SIZE,    # e_phentsize
        1,            # e_phnum
        64,           # e_shentsize
        0,            # e_shnum
        0,            # e_shstrndx
    )

    phdr = struct.pack(
        "<IIQQQQQQ",
        1,            # p_type = PT_LOAD
        5,            # p_flags = R|X
        0,            # p_offset
        BASE,         # p_vaddr
        BASE,         # p_paddr
        total,        # p_filesz
        total,        # p_memsz
        0x1000,       # p_align
    )

    return ehdr + phdr + code


def main():
    args = [a for a in sys.argv[1:]]
    out = "kgslprobe"
    req = 0xC0180902
    if args:
        out = args[0]
    if len(args) > 1:
        req = int(args[1], 0)
    code, i_bmi, i_fail = build_code(req)
    blob = build_elf(code)
    with open(out, "wb") as f:
        f.write(blob)
    print(f"[+] wrote {out}: {len(blob)} bytes, code={len(code)} bytes, "
          f"entry=0x{0x400000 + 120:x}, ioctl_req=0x{req:08X}")
    print(f"[+] instructions: {len(code)//4}, b.mi at #{i_bmi}, fail label at #{i_fail}")


if __name__ == "__main__":
    main()
