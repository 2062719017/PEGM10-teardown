#!/usr/bin/env python3
"""
kallsyms_parse.py — 从 ARM64 内核镜像里还原 kallsyms 符号表

原理：CONFIG_KALLSYMS=y 的内核内嵌压缩符号表，布局为：
    kallsyms_offsets[]      每个符号相对基址的 32 位偏移（CONFIG_KALLSYMS_BASE_RELATIVE）
    kallsyms_num_syms       符号总数
    kallsyms_names[]        压缩名字流：[len][token...]，len 为 token 个数（可能多字节）
    kallsyms_markers[]      每 256 个符号的偏移索引
    kallsyms_token_table[]  256 个以 \\0 分隔的子串
    kallsyms_token_index[]  256 个 u16，指向 token_table 内偏移

定位策略：
  1. 在镜像里找 token_table：一段包含大量短字符串、以 \\0 密集分隔的区域
  2. 从 token_table 往前找 token_index（256 个 u16，递增且都小于 token_table 长度）
  3. 从 token_index 往前找 names 流
  4. 验证解压出的第一个符号是否像内核函数名

用法：
    python kallsyms_parse.py fw\\kernel.bin [--find SYMBOL]
"""

import struct
import sys
import re

def load(path):
    with open(path, 'rb') as f:
        return f.read()


def find_token_table(data):
    """启发式定位 token_table：搜索大量短字符串密集排列的区域"""
    # token_table 里通常包含这些高频子串
    seeds = [b'\x00_init\x00', b'\x00_alloc\x00', b'\x00_exit\x00', b'\x00free\x00']
    best = None
    for seed in seeds:
        idx = data.find(seed)
        while idx != -1:
            start = idx
            # 向前回退到区域起点（找连续的 \0 分隔字符串）
            back = 0
            while back < 4096 and start - back > 0:
                if data[start - back - 1:start - back] == b'\x00':
                    back += 1
                    if back > 64:
                        break
                else:
                    break
            # 统计该区域后面的可打印比例
            region = data[idx:idx + 8192]
            printable = sum(1 for b in region if 32 <= b < 127 or b == 0)
            if printable > len(region) * 0.9:
                if best is None or printable > best[2]:
                    best = (idx, region, printable)
            idx = data.find(seed, idx + 1)
    return best[0] if best else None


def try_parse(data, token_table_off):
    """
    从 token_table 位置向前推 token_index、markers、names、num_syms、offsets，
    解开符号表并返回 [(addr_offset, name), ...]
    """
    # token_table 前面紧邻 token_index：256 个 u16
    ti_off = token_table_off - 512
    if ti_off < 0:
        return None

    # 先重建 token_table 的边界：从 ti_off 往后，token 0..255
    try:
        token_index = struct.unpack_from('<256H', data, ti_off)
    except struct.error:
        return None

    # 校验：token_index 应单调不减，且都小于一个合理长度
    if any(token_index[i] > token_index[i+1] for i in range(255)):
        return None
    tt_len = token_index[255] + 64
    token_table = data[token_table_off:token_table_off + tt_len]

    def token(i):
        s = token_index[i]
        e = token_table.find(b'\x00', s)
        if e < 0:
            e = len(token_table)
        return token_table[s:e]

    # token_index 前面是 names 流，再前面是 num_syms、offsets
    # names 流长度未知，从 num_syms 反推：num_syms 是个 4 或 8 字节整数
    # 试探：在 ti_off 前 16MB 范围内找 (num_syms, names) 组合
    for num_off in range(ti_off - 4, max(0, ti_off - 0x2000000), -4):
        num = struct.unpack_from('<I', data, num_off)[0]
        if not (10000 < num < 400000):
            continue
        names_off = num_off + 4
        # 尝试解码 num 个符号名
        pos = names_off
        syms = []
        ok = True
        for _ in range(min(num, 200)):
            if pos >= ti_off:
                ok = False
                break
            ln = data[pos]
            pos += 1
            if ln & 0x80:
                ln = (ln & 0x7F) | (data[pos] << 7)
                pos += 1
            if ln == 0 or ln > 64 or pos + ln > ti_off:
                ok = False
                break
            name = b''.join(token(data[pos + k]) for k in range(ln))
            pos += ln
            try:
                syms.append(name.decode('ascii'))
            except UnicodeDecodeError:
                ok = False
                break
        if ok and syms and re.match(r'^[A-Za-z_][A-Za-z0-9_.]*$', syms[0]):
            # 找到 names 流，现在往前找 offsets 数组
            offsets_off = num_off - num * 4
            if offsets_off < 0:
                continue
            return {
                'num': num,
                'names_off': names_off,
                'offsets_off': offsets_off,
                'token_index': token_index,
                'token_table': token_table,
                'sample': syms[:10],
            }
    return None


def decode_all(data, info):
    token_index = info['token_index']
    token_table = info['token_table']

    def token(i):
        s = token_index[i]
        e = token_table.find(b'\x00', s)
        if e < 0:
            e = len(token_table)
        return token_table[s:e]

    num = info['num']
    pos = info['names_off']
    names = []
    for _ in range(num):
        ln = data[pos]; pos += 1
        if ln & 0x80:
            ln = (ln & 0x7F) | (data[pos] << 7); pos += 1
        name = b''.join(token(data[pos + k]) for k in range(ln))
        pos += ln
        names.append(name.decode('ascii', 'replace'))

    offs = struct.unpack_from('<%dI' % num, data, info['offsets_off'])
    return names, offs


def main():
    path = sys.argv[1]
    want = None
    if '--find' in sys.argv:
        want = sys.argv[sys.argv.index('--find') + 1]

    data = load(path)
    print(f"[*] loaded {len(data)} bytes")

    tt = find_token_table(data)
    if tt is None:
        print("[!] token_table 未定位")
        return
    print(f"[+] token_table @ 0x{tt:x}")

    info = try_parse(data, tt)
    if not info:
        print("[!] 解析失败")
        return
    print(f"[+] num_syms = {info['num']}")
    print(f"[+] names @ 0x{info['names_off']:x}  offsets @ 0x{info['offsets_off']:x}")
    print(f"[+] sample: {info['sample']}")

    names, offs = decode_all(data, info)
    print(f"[+] 解出 {len(names)} 个符号")

    if want:
        for n, o in zip(names, offs):
            if want in n:
                print(f"    0x{o:08x}  {n}")
    else:
        for n, o in list(zip(names, offs))[:20]:
            print(f"    0x{o:08x}  {n}")


if __name__ == '__main__':
    main()
