#!/usr/bin/env python3
"""
pe_res.py — 列出 PE 文件的资源目录（用于从 Zadig 里找内嵌的驱动文件）

libwdi 把 WinUSB/libusbK 的驱动文件（.inf/.cat/.sys）作为资源嵌进可执行文件，
本脚本遍历 PE 资源树，打印类型/名称/语言和大小，并可按索引导出。
"""

import struct
import sys


def parse(data):
    if data[:2] != b'MZ':
        raise SystemExit('不是 PE 文件')
    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b'PE\x00\x00':
        raise SystemExit('PE 签名不对')
    coff = e_lfanew + 4
    machine, nsec, _, _, _, optsz, _ = struct.unpack_from('<HHIIIHH', data, coff)
    opt = coff + 20
    magic = struct.unpack_from('<H', data, opt)[0]
    pe32p = (magic == 0x20B)
    # 数据目录表偏移
    dd_off = opt + (112 if pe32p else 96)
    # 资源表是第 3 个目录（索引 2）
    rva, size = struct.unpack_from('<II', data, dd_off + 2 * 8)
    print(f"[+] PE{'32+' if pe32p else '32'}  sections={nsec}  "
          f"resource RVA=0x{rva:x} size=0x{size:x}")

    # 节表
    sec_off = opt + optsz
    secs = []
    for i in range(nsec):
        o = sec_off + i * 40
        name = data[o:o + 8].rstrip(b'\x00').decode('latin1')
        vsize, vaddr, rawsize, rawptr = struct.unpack_from('<IIII', data, o + 8)
        secs.append((name, vaddr, vsize, rawptr, rawsize))
        print(f"    {name:10s} VA=0x{vaddr:08x} vsz=0x{vsize:x} raw=0x{rawptr:x} raws=0x{rawsize:x}")

    def rva2off(r):
        for name, vaddr, vsize, rawptr, rawsize in secs:
            if vaddr <= r < vaddr + max(vsize, rawsize):
                return rawptr + (r - vaddr)
        return None

    res_off = rva2off(rva)
    if res_off is None:
        print('[!] 资源段未找到')
        return

    def walk(dir_off, level, path):
        chars, ts, major, minor, n_named, n_id = struct.unpack_from('<IIHHHH', data, dir_off)
        entries = dir_off + 16
        out = []
        for i in range(n_named + n_id):
            o = entries + i * 8
            name_or_id, off_to_data = struct.unpack_from('<II', data, o)
            if name_or_id & 0x80000000:
                # 命名字符串
                so = res_off + (name_or_id & 0x7FFFFFFF)
                ln = struct.unpack_from('<H', data, so)[0]
                nm = data[so + 2:so + 2 + ln * 2].decode('utf-16-le', 'replace')
            else:
                nm = name_or_id
            sub = off_to_data & 0x7FFFFFFF
            is_dir = bool(off_to_data & 0x80000000)
            if is_dir:
                out += walk(res_off + sub, level + 1, path + [str(nm)])
            else:
                do = res_off + sub
                data_rva, dsize, cp, _ = struct.unpack_from('<IIII', data, do)
                doff = rva2off(data_rva)
                out.append((path + [str(nm)], dsize, doff))
        return out

    items = walk(res_off, 0, [])
    print(f"[+] 资源条目 {len(items)} 个:")
    for path, size, off in items:
        print(f"    {'/'.join(path):46s} size={size:>9} off=0x{off or 0:x}")
    return items


if __name__ == '__main__':
    data = open(sys.argv[1], 'rb').read()
    items = parse(data)
    if len(sys.argv) > 2 and items:
        # 导出全部资源到目录
        import os
        outdir = sys.argv[2]
        os.makedirs(outdir, exist_ok=True)
        for path, size, off in items:
            if off is None or size == 0:
                continue
            fn = '_'.join(path).replace('/', '_')
            open(os.path.join(outdir, fn), 'wb').write(data[off:off + size])
            print(f"    saved {fn} ({size} bytes)")
