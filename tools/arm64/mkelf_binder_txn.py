#!/usr/bin/env python3
"""
mkelf_binder_txn.py — 从 adb shell 发起一次真实 binder 事务

先打一发 one-way 事务到 servicemanager(handle 0)，验证「一页缓冲区足以承载事务」。
one-way 不需要回复，所以不会阻塞；成功即证明写路径全程贯通。

等效 C：

    fd  = open("/dev/binder", O_RDWR);
    buf = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);

    // 写缓冲区：[0..3] BC_TRANSACTION，紧跟 binder_transaction_data
    uint8_t wbuf[68] = {0};
    *(uint32_t*)(wbuf + 0)  = BC_TRANSACTION;      // 0x00000000
    struct binder_transaction_data *tx = (void*)(wbuf + 4);
    tx->target.handle = 0;        // servicemanager
    tx->code          = 4;        // SCMGR_LIST_SERVICES
    tx->flags         = TF_ONE_WAY;   // 0x01
    // data_size / offsets_size 全 0（空 parcel）

    struct binder_write_read bwr = {
        .write_size   = 68,
        .write_buffer = (uintptr_t)wbuf,
        .read_size    = 0,
        .read_buffer  = 0,
    };
    ioctl(fd, BINDER_WRITE_READ, &bwr);

        binder_write_read 布局（48 字节）：
        +0  write_size      +8  write_consumed  +16 write_buffer
        +24 read_size       +32 read_consumed   +40 read_buffer

        binder_transaction_data 布局（64 字节，紧跟在 4 字节命令之后）：
        +0  target(handle u32)   +8  cookie        +16 code(u32)  +20 flags(u32)
        +24 sender_pid(u32)      +28 sender_euid   +32 data_size  +40 offsets_size
        +48 data.ptr.buffer      +56 data.ptr.offsets

输出 3 字节：
    [0] mmap 成功 ?
    [1] ioctl(BINDER_WRITE_READ) 返回值低字节
    [2] write_consumed 低字节（被驱动消费掉多少字节，应为 68）

用法：
    python mkelf_binder_txn.py btxn [code] [flags]
    adb push btxn /data/local/tmp/ && adb shell 'chmod 755 /data/local/tmp/btxn; /data/local/tmp/btxn'
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

def strb(rt, rn, off):
    return 0x39000000 | ((off & 0xFFF) << 10) | ((rn & 0x1F) << 5) | (rt & 0x1F)

def ldr64(rt, rn, off):
    return 0xF9400000 | (((off // 8) & 0xFFF) << 10) | ((rn & 0x1F) << 5) | (rt & 0x1F)

SVC = 0xD4000001

# 布局
PATH_OFF   = 0      # 24 字节
STAT_OFF   = 32     # 4 字节状态
BWR_OFF    = 64     # binder_write_read 48 字节
WBUF_OFF   = 128    # 写缓冲：4 + 64 = 68 字节
TX_OFF     = WBUF_OFF + 4

FRAME = 256


def load_const(ins, reg, value):
    ins.append(movz64(reg, value & 0xFFFF))
    for sh in (16, 32, 48):
        part = (value >> sh) & 0xFFFF
        if part:
            ins.append(movk64(reg, part, sh))


def build(code=4, flags=1, mmap_size=1040384, bc_cmd=None, payload=64, do_mmap=True, hexdata=None, wsize_override=None, withread=False, anonbuf=False):
    path = b"/dev/binder\x00".ljust(24, b"\x00")
    p0, p1, p2 = (struct.unpack("<Q", path[i:i+8])[0] for i in (0, 8, 16))

    ins = []
    ins.append(0xD1000000 | ((FRAME & 0xFFF) << 10) | (31 << 5) | 31)   # sub sp, sp, #FRAME

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

    # 清零 [sp+32 .. sp+255]，覆盖状态区 / bwr / 写缓冲
    for off in range(32, FRAME, 16):
        ins.append(stp(31, 31, 31, off))

    # 记录真实 sp，便于核对 write_buffer 是否正确
    ins.append(0x910003E9)                     # mov x9, sp
    ins.append(str64(9, 31, STAT_OFF + 8))     # [sp+40] = sp

    # openat(AT_FDCWD, sp, O_RDWR)
    ins.append(0x92800C60)                     # movn x0, #99
    ins.append(add_imm(1, 31, PATH_OFF))
    ins.append(0xD2800042)                     # movz x2, #2
    ins.append(0xD2800708)                     # movz x8, #56
    ins.append(SVC)
    ins.append(0x91000015)                     # mov x21, x0 (fd)
    ins.append(0xF100001F)                     # cmp x0, #0
    b_open = len(ins); ins.append(0)

    # mmap（可按需跳过）
    if do_mmap:
        ins.append(0xD2800000)                     # movz x0, #0
        load_const(ins, 1, mmap_size)
        ins.append(0xD2800022)                     # movz x2, #1
        ins.append(0xD2800043)                     # movz x3, #2
        ins.append(0x910002A4)                     # mov x4, x21
        ins.append(0xD2800005)                     # movz x5, #0
        ins.append(0xD2801BC8)                     # movz x8, #222 (mmap)
        ins.append(SVC)
        ins.append(0x91000016)                     # mov x22, x0
        ins.append(0xF10002DF)                     # cmp x22, #0
        b_mm = len(ins); ins.append(0)
    else:
        b_mm = None
    ins.append(0xD2800029)                     # movz w9, #1
    ins.append(strb(9, 31, STAT_OFF))          # status[0] = 1

    # 可选：用 mmap 匿名页作为写缓冲（验证栈页是否被内核拒绝）
    if anonbuf:
        ins.append(0xD2800000)                     # movz x0, #0
        load_const(ins, 1, 4096)                   # len
        ins.append(0xD2800062)                     # movz x2, #3 (RW)
        ins.append(movz64(3, 0x22))                # MAP_PRIVATE|MAP_ANONYMOUS
        ins.append(0x92800004)                     # movn x4, #0 -> -1  (fd)
        ins.append(0xD2800005)                     # movz x5, #0
        ins.append(0xD2801BC8)                     # movz x8, #222
        ins.append(SVC)
        ins.append(0x91000017)                     # mov x23, x0 (buf)
        ins.append(0xF10002FF)                     # cmp x23, #0
        b_anon = None
    else:
        b_anon = None
    b_anon_idx = None

    # ---- 构造写缓冲 ----
    if hexdata is not None:
        data = bytes.fromhex(hexdata)
        chunk = data.ljust(((len(data) + 15) // 16) * 16, b"\x00")
        for i in range(0, len(chunk), 8):
            val = struct.unpack("<Q", chunk[i:i+8])[0]
            if val == 0:
                continue
            ins.append(movz64(9, val & 0xFFFF))
            for sh in (16, 32, 48):
                part = (val >> sh) & 0xFFFF
                if part:
                    ins.append(movk64(9, part, sh))
            ins.append(str64(9, 23, i) if anonbuf else str64(9, 31, WBUF_OFF + i))
        wsize = wsize_override if wsize_override is not None else len(data)
    elif bc_cmd is None:
        # 事务：首 4 字节 BC_TRANSACTION(0x00)，清零时已为 0
        ins.append(movz32(9, code & 0xFFFF))
        ins.append(str32(9, 23, 20) if anonbuf else str32(9, 31, TX_OFF + 16))      # code
        ins.append(movz32(9, flags & 0xFFFF))
        ins.append(str32(9, 23, 24) if anonbuf else str32(9, 31, TX_OFF + 20))      # flags
        wsize = 4 + 64
    else:
        # 纯命令：只写 4 字节命令字
        ins.append(movz32(9, bc_cmd & 0xFFFF))
        if bc_cmd > 0xFFFF:
            ins.append(movk32(9, (bc_cmd >> 16) & 0xFFFF, 16))
        ins.append(str32(9, 23, 0) if anonbuf else str32(9, 31, WBUF_OFF))
        wsize = 4 + payload if payload else 4

    # libbinder 的完整初始化序列：open → mmap → VERSION → SET_MAX_THREADS
    # BINDER_VERSION
    ins.append(0x910002A0)                     # mov x0, x21
    ins.append(movz32(1, 0x6209))
    ins.append(movk32(1, 0xC004, 16))
    ins.append(add_imm(2, 31, STAT_OFF + 16))  # &ver
    ins.append(0xD28003A8)
    ins.append(SVC)

    # BINDER_SET_MAX_THREADS(_IOW('b',5,__u32) = 0x40046205)，参数指向一个 int
    ins.append(movz32(9, 15))                  # 15 个线程，libbinder 默认
    ins.append(str32(9, 31, STAT_OFF + 24))
    ins.append(0x910002A0)
    ins.append(movz32(1, 0x6205))
    ins.append(movk32(1, 0x4004, 16))
    ins.append(add_imm(2, 31, STAT_OFF + 24))
    ins.append(0xD28003A8)
    ins.append(SVC)

    # ---- 构造 binder_write_read ----
    load_const(ins, 9, wsize)
    ins.append(str64(9, 31, BWR_OFF + 0))
    ins.append(0x910002E9 if anonbuf else add_imm(9, 31, WBUF_OFF))   # write_buffer
    ins.append(str64(9, 31, BWR_OFF + 16))
    if do_mmap and withread:
        # read_size = mmap 尺寸，read_buffer = mmap 返回地址（libbinder 的正常模式）
        load_const(ins, 9, mmap_size)
        ins.append(str64(9, 31, BWR_OFF + 24))
        ins.append(str64(22, 31, BWR_OFF + 40))

    # ---- ioctl BINDER_WRITE_READ ----
    ins.append(0x910002A0)                     # mov x0, x21
    ins.append(movz32(1, 0x6201))
    ins.append(movk32(1, 0xC030, 16))          # _IOWR('b',1,48)
    ins.append(add_imm(2, 31, BWR_OFF))
    ins.append(0xD28003A8)                     # movz x8, #29
    ins.append(SVC)
    ins.append(strb(0, 31, STAT_OFF + 1))      # status[1] = rc

    # 读回 write_consumed
    ins.append(ldr64(9, 31, BWR_OFF + 8))
    ins.append(strb(9, 31, STAT_OFF + 2))      # status[2] = write_consumed 低字节

    # 输出：4 字节状态 + 48 字节 BWR 原始内容 + 8 字节写缓冲头
    end = len(ins)
    ins.append(0xD2800020)                     # movz x0, #1
    ins.append(add_imm(1, 31, STAT_OFF))
    ins.append(0xD2800082)                     # movz x2, #4
    ins.append(0xD2800808)                     # movz x8, #64
    ins.append(SVC)
    ins.append(0xD2800020)
    ins.append(add_imm(1, 31, BWR_OFF))
    ins.append(0xD2800602)                     # movz x2, #48
    ins.append(0xD2800808)
    ins.append(SVC)
    ins.append(0xD2800020)
    ins.append(add_imm(1, 31, WBUF_OFF))
    ins.append(0xD2800102)                     # movz x2, #8
    ins.append(0xD2800808)
    ins.append(SVC)
    ins.append(0xD2800000)                     # exit 0
    ins.append(0xD2800BA8)
    ins.append(SVC)

    fail = len(ins)
    ins.append(0xD2800020)
    ins.append(add_imm(1, 31, STAT_OFF))
    ins.append(0xD2800082)
    ins.append(0xD2800808)
    ins.append(SVC)
    ins.append(0x910002A0)                     # exit(errno)
    ins.append(0xD2800BA8)
    ins.append(SVC)

    ins[b_open] = 0x54000000 | (((fail - b_open) & 0x7FFFF) << 5) | 4
    if b_mm is not None:
        ins[b_mm] = 0x54000000 | (((end - b_mm) & 0x7FFFF) << 5) | 4
    return b"".join(struct.pack("<I", i) for i in ins)


def elf(code_bytes):
    BASE = 0x400000
    EH, PH = 64, 56
    off = EH + PH
    total = off + len(code_bytes)
    e_ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    ehdr = struct.pack("<16sHHIQQQIHHHHHH", e_ident, 2, 183, 1,
                       BASE + off, EH, 0, 0, EH, PH, 1, 64, 0, 0)
    phdr = struct.pack("<IIQQQQQQ", 1, 5, 0, BASE, BASE, total, total, 0x1000)
    return ehdr + phdr + code_bytes


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "btxn"
    code = int(sys.argv[2], 0) if len(sys.argv) > 2 else 4
    flags = int(sys.argv[3], 0) if len(sys.argv) > 3 else 1
    bccmd = int(sys.argv[4], 0) if len(sys.argv) > 4 else None
    pl = int(sys.argv[5], 0) if len(sys.argv) > 5 else 64
    nomm = "--nommap" in sys.argv
    hexdata = None
    wov = None
    if "--hex" in sys.argv:
        i = sys.argv.index("--hex")
        hexdata = sys.argv[i+1]
    if "--wsize" in sys.argv:
        i = sys.argv.index("--wsize")
        wov = int(sys.argv[i+1], 0)
    cb = build(code, flags, bc_cmd=bccmd, payload=pl, do_mmap=not nomm, anonbuf=("--anonbuf" in sys.argv),
               hexdata=hexdata, wsize_override=wov, withread=("--withread" in sys.argv))
    open(out, "wb").write(elf(cb))
    print(f"[+] {out}: {len(cb)+120} bytes, code={code}, flags={flags}, "
          f"bc_cmd={bccmd}, payload={pl}")
