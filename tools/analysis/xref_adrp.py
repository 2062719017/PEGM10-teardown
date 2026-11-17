#!/usr/bin/env python3
"""
xref_adrp.py — 通过 ADRP+ADD 交叉引用在 ARM64 内核镜像里定位函数

原理：ARM64 用 PC 相对寻址加载地址，典型序列：
    ADRP Xd, page        ; Xd = (PC & ~0xFFF) + (imm << 12)
    ADD  Xd, Xd, #off    ; Xd += off  -> 指向目标
反向搜索：给定目标的虚拟地址，扫描全镜像找能算出该地址的 ADRP+ADD 对。

用法：
    python xref_adrp.py fw/kernel.bin <目标文件偏移> [--base 0xffff000008008000]
"""

import sys
import struct

def decode_adrp(w, pc):
    if (w & 0x9F000000) != 0x90000000:
        return None
    rd = w & 0x1F
    immlo = (w >> 29) & 0x3
    immhi = (w >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= (1 << 21)
    return rd, (pc & ~0xFFF) + (imm << 12)


def decode_add_imm(w):
    # ADD (immediate) 64-bit: 0x91000000
    if (w & 0xFFC00000) != 0x91000000:
        return None
    rd = w & 0x1F
    rn = (w >> 5) & 0x1F
    imm = (w >> 10) & 0xFFF
    shift = (w >> 22) & 0x3
    if shift == 1:
        imm <<= 12
    return rd, rn, imm


def main():
    path = sys.argv[1]
    tgt_off = int(sys.argv[2], 0)
    base = 0xffff000008008000
    if '--base' in sys.argv:
        base = int(sys.argv[sys.argv.index('--base') + 1], 0)

    data = open(path, 'rb').read()
    target = base + tgt_off
    print(f"[*] 目标文件偏移 0x{tgt_off:x} -> VA 0x{target:x}")

    hits = []
    n = len(data)
    step = 4
    # 扫描：把每条指令当作潜在 ADRP，检查其后若干条内是否有匹配的 ADD
    for off in range(0, n - 16, step):
        w = struct.unpack_from('<I', data, off)[0]
        r = decode_adrp(w, base + off)
        if not r:
            continue
        rd, page = r
        # 在该 ADRP 后 64 字节内找 ADD Xd, Xd, #imm
        for k in range(1, 16):
            o2 = off + k * 4
            if o2 + 4 > n:
                break
            w2 = struct.unpack_from('<I', data, o2)[0]
            a = decode_add_imm(w2)
            if a:
                rd2, rn2, imm = a
                if rd2 == rd and rn2 == rd and page + imm == target:
                    hits.append((off, page, imm, k))
                    break
            # 也接受 LDR/其它形式：跳过
    print(f"[+] 找到 {len(hits)} 处引用")
    for off, page, imm, k in hits[:20]:
        stores = ''
        print(f"    ADRP @ 0x{off:08x} (VA 0x{base+off:x})  page=0x{page:x} + 0x{imm:x}  (+{k} insns)")


if __name__ == '__main__':
    main()
