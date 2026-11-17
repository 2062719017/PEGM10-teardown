#!/usr/bin/env python3
"""
find_kallsyms.py — 在 ARM64 内核镜像里定位 kallsyms 压缩符号表

kallsyms_token_table 的统计特征：
  - 长度 1~16 KB
  - 字节几乎全是可打印 ASCII 或 0x00
  - 0x00 密度极高（每个 token 一个）
  - 平均字符串长度 3~12 字节
  - 不含长串空格或换行

kallsyms_names 的统计特征：
  - 一长段（几百 KB ~ 数 MB）以 [len][tokens] 编码的流
  - 字节值分布宽（0~255），但几乎不出现 0x00
"""

import sys
import struct

PRINTABLE = bytes(range(32, 127))


def load(path):
    with open(path, 'rb') as f:
        return f.read()


def scan_token_table(data, win=1024):
    """滑动窗口找 == 高密度短字符串区 == """
    cands = []
    step = 256
    for off in range(0, len(data) - win, step):
        blk = data[off:off + win]
        printable = sum(1 for b in blk if 32 <= b < 127)
        zeros = blk.count(0)
        # token_table: 可打印 + 零 应该 ≈ 100%
        if printable + zeros < win * 0.995:
            continue
        if zeros < win * 0.03 or zeros > win * 0.30:
            continue
        # 平均串长
        runs = [len(s) for s in blk.split(b'\x00') if s]
        if not runs:
            continue
        avg = sum(runs) / len(runs)
        if not (3 <= avg <= 14):
            continue
        cands.append((off, printable, zeros, round(avg, 1)))
    # 合并相邻候选
    merged = []
    for c in cands:
        if merged and c[0] - merged[-1][1] <= 2048:
            merged[-1] = (merged[-1][0], c[0] + win, merged[-1][2] + 1, c)
        else:
            merged.append((c[0], c[0] + win, 1, c))
    return merged


def main():
    path = sys.argv[1]
    data = load(path)
    print(f"[*] {path}: {len(data)} bytes")
    print("[*] 扫描 token_table 候选区 ...")
    merged = scan_token_table(data)
    print(f"[+] 找到 {len(merged)} 个候选区域")
    for start, end, n, last in merged[:20]:
        print(f"    0x{start:08x} - 0x{end:08x}   ({end-start} B, avg_len={last[3]})")
        # 打印该区域开头片段
        seg = data[start:start + 200]
        s = ''.join(chr(b) if 32 <= b < 127 else ('|' if b == 0 else '.') for b in seg)
        print(f"      {s[:180]}")


if __name__ == '__main__':
    main()
