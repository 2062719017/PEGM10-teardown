#!/usr/bin/env python3
"""
analyze_mbn.py — 解析 ARM32 ELF（oplus_sec.mbn）的结构与字符串

输出：
  - ELF 头字段
  - program headers（段）
  - section headers（节）
  - 提取可打印字符串，并按关键词过滤
"""

import struct
import sys
import re

KEYWORDS = [
    'unlock', 'lock', 'secure', 'devinfo', 'verify', 'sign', 'crypt',
    'fail', 'error', 'aboot', 'abl', 'boot', 'seccfg', 'otp', 'fuse',
    'keymaster', 'qsee', 'tz', 'trustzone', 'avb', 'vbmeta', 'dm-verity',
    'OPPO', 'oplus', 'eng', 'factory', 'test', 'serial', 'imei',
]


def main():
    path = sys.argv[1]
    data = open(path, 'rb').read()
    print(f"[*] {path}: {len(data)} bytes")

    if data[:4] != b'\x7fELF':
        print("[!] 不是 ELF")
        return

    ei_class = data[4]
    ei_data = data[5]
    e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags, e_ehsize, \
        e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = \
        struct.unpack_from('<HHIIIIIHHHHHH', data, 16)

    print(f"[+] type={e_type}(2=EXEC,3=DYN) class={ei_class}(1=32bit) "
          f"data={ei_data}(1=LE) machine={e_machine}(40=ARM)")
    print(f"[+] entry=0x{e_entry:x} phoff=0x{e_phoff:x} phnum={e_phnum} "
          f"shoff=0x{e_shoff:x} shnum={e_shnum} shstrndx={e_shstrndx}")

    # program headers (32-bit)
    print("\n[*] program headers:")
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = \
            struct.unpack_from('<IIIIIIII', data, off)
        tn = {1: 'LOAD', 2: 'DYNAMIC', 3: 'INTERP', 4: 'NOTE', 6: 'PHDR',
              7: 'TLS', 0x6474e550: 'GNU_EH_FRAME', 0x6474e551: 'GNU_STACK',
              0x6474e552: 'GNU_RELRO', 0x70000000: 'ARM_EXIDX',
              0x70000001: 'ARM_EXIDX'}.get(p_type, hex(p_type))
        fl = ''.join(c for c, b in zip('RWX', (4, 2, 1)) if p_flags & b)
        print(f"    [{i}] {tn:14s} file=0x{p_offset:06x} vaddr=0x{p_vaddr:08x} "
              f"filesz=0x{p_filesz:06x} memsz=0x{p_memsz:06x} {fl}")

    # section headers
    if e_shoff:
        print("\n[*] section headers:")
        shstr_off = 0
        if e_shstrndx:
            o = e_shoff + e_shstrndx * e_shentsize
            _, _, _, _, shstr_off, shstr_sz, _, _, _, _ = \
                struct.unpack_from('<IIIIIIIIII', data, o)
        for i in range(e_shnum):
            o = e_shoff + i * e_shentsize
            name, typ, flags, addr, offset, size, link, info, align, entsize = \
                struct.unpack_from('<IIIIIIIIII', data, o)
            nm = ''
            if shstr_off:
                e = data.find(b'\x00', shstr_off + name)
                nm = data[shstr_off + name:e].decode('ascii', 'replace')
            print(f"    [{i:2d}] {nm:20s} type={typ} addr=0x{addr:08x} "
                  f"off=0x{offset:06x} size=0x{size:x}")

    # strings
    print("\n[*] 关键词命中:")
    seen = set()
    for m in re.finditer(rb'[\x20-\x7e]{5,}', data):
        s = m.group().decode('ascii', 'replace')
        low = s.lower()
        for kw in KEYWORDS:
            if kw.lower() in low and s not in seen:
                seen.add(s)
                print(f"    0x{m.start():06x}  {s[:100]}")
                break


if __name__ == '__main__':
    main()
