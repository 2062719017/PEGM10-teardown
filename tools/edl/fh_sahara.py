import rawlibusb, struct, time, sys

VID, PID, EP_IN, EP_OUT = 0x05C6, 0x9008, 0x81, 0x01
PROG = r'C:\Users\Qwistzz\Downloads\Compressed\PEGM10domestic_11_13.1.0.2101CN01_2025061222420157\IMAGES\prog_firehose_ddr.elf'

NAMES = {0x01: 'HELLO', 0x02: 'HELLO_RESP', 0x03: 'READ_DATA', 0x04: 'END_OF_IMAGE',
         0x05: 'DONE', 0x06: 'DONE_RESP', 0x07: 'RESET', 0x08: 'RESET_RESP',
         0x09: 'MEMORY_DEBUG', 0x0A: 'MEMORY_READ', 0x0B: 'CMD_READY',
         0x0C: 'CMD_SWITCH_MODE', 0x0D: 'CMD_EXEC', 0x0E: 'CMD_EXEC_RESP',
         0x0F: 'CMD_EXEC_DATA', 0x12: '64B_READ_DATA', 0x13: '64B_END_OF_IMAGE'}


def open_dev(retries=60, delay=0.4):
    last = None
    for i in range(retries):
        u = None
        try:
            u = rawlibusb.RawLibUSB()
            u.open(VID, PID, 0)
            return u
        except Exception as e:
            last = e
            if u:
                try:
                    u.close()
                except Exception:
                    pass
            time.sleep(delay)
    raise SystemExit(f'无法打开: {last}')


def read_exact(u, n, timeout=4000):
    buf = b''
    deadline = time.time() + timeout / 1000.0
    while len(buf) < n:
        remain_ms = int(max(100, (deadline - time.time()) * 1000))
        try:
            chunk = u.read(EP_IN, n - len(buf), remain_ms)
        except rawlibusb.LibUSBTimeout:
            break
        if not chunk:
            break
        buf += chunk
    return buf


def drain(u, rounds=6):
    total = 0
    for _ in range(rounds):
        try:
            d = u.read(EP_IN, 256, 300)
            if not d:
                break
            total += len(d)
        except rawlibusb.LibUSBTimeout:
            break
        except Exception:
            break
    return total


def send_done_variant(u, variant):
    """variant: 8 = cmd+len, 12 = cmd+len+image_id+status"""
    if variant == 8:
        pkt = struct.pack('<II', 0x05, 8)
    else:
        pkt = struct.pack('<IIII', 0x05, 12, 13, 0)
    u.write(EP_OUT, pkt)
    return pkt


def main():
    variant = int(sys.argv[1]) if len(sys.argv) > 1 else 12
    data = open(PROG, 'rb').read()
    print(f'[*] programmer {len(data)} 字节, DONE 包长度 = {variant}')

    u = open_dev()
    print('[+] 设备已打开')
    n = drain(u)
    if n:
        print(f'[i] 清掉残留 {n} 字节')

    # 若设备当前是失败循环，先发一次 RESET 再重来
    print('[*] 发送 SAHARA_RESET 清理状态 ...')
    u.write(EP_OUT, struct.pack('<II', 0x07, 8))
    time.sleep(0.5)
    n = drain(u, 4)
    print(f'[i] RESET 后清理 {n} 字节')

    print('[*] 重新连接（等待设备重新枚举）...')
    u.close()
    time.sleep(1)
    u = open_dev()
    print('[+] 重新打开成功')
    n = drain(u, 4)
    if n:
        print(f'[i] 再清 {n} 字节')

    # 读 HELLO
    print('[*] 读 HELLO ...')
    hdr = read_exact(u, 8, 5000)
    if len(hdr) < 8:
        print('[!] 没收到 HELLO，当前状态可能是 END_OF_IMAGE')
        # 试着处理：读完整包
        if hdr:
            print(f'    已读 {len(hdr)}B: {hdr.hex()}')
        u.close()
        return
    cmd, ln = struct.unpack('<II', hdr)
    print(f'    cmd=0x{cmd:x} ({NAMES.get(cmd,"?")}) len={ln}')
    if cmd == 0x04:
        body = read_exact(u, ln - 8, 3000)
        print(f'    END_OF_IMAGE body: {body.hex()}')
        iid, st = struct.unpack('<II', body[:8]) if len(body) >= 8 else (0, 0)
        print(f'    image={iid} status={st}')
        print(f'[*] 用 length={variant} 的 DONE 回应 ...')
        send_done_variant(u, variant)
        print('[+] 已发 DONE')
        r = read_exact(u, 8, 3000)
        if r:
            c2, l2 = struct.unpack('<II', r[:8])
            print(f'[<] cmd=0x{c2:x} ({NAMES.get(c2,"?")}) len={l2}')
        else:
            print('[-] 无响应')
        u.close()
        return

    if cmd != 0x01:
        print('[!] 意外的包')
        u.close()
        return

    body = read_exact(u, ln - 8, 3000)
    v, vmin, mp, mode = struct.unpack('<IIII', body[:16])
    print(f'[+] HELLO version={v} min={vmin} maxpkt={mp} mode={mode}')

    # 回 HELLO_RESP
    resp = struct.pack('<IIIIII6I', 0x02, 48, v, vmin, mp, mode, 0, 0, 0, 0, 0, 0)
    u.write(EP_OUT, resp)
    print('[+] 已回 HELLO_RESP')

    # 主循环
    sent = 0
    loop = 0
    while loop < 5000:
        loop += 1
        h = read_exact(u, 8, 8000)
        if len(h) < 8:
            print('[!] 读取超时，结束')
            break
        c, l = struct.unpack('<II', h)
        name = NAMES.get(c, '?')

        if c == 0x03:                     # READ_DATA
            b = read_exact(u, l - 8, 4000)
            iid, off, dlen = struct.unpack('<IQI', b[:16])
            chunk = data[off:off + dlen]
            if len(chunk) < dlen:
                chunk += b'\x00' * (dlen - len(chunk))
            u.write(EP_OUT, chunk)
            sent += len(chunk)
            print(f'    READ_DATA image={iid} off=0x{off:x} len={dlen} | {sent}/{len(data)}')

        elif c == 0x12:                   # 64B_READ_DATA
            b = read_exact(u, l - 8, 4000)
            iid, off, dlen = struct.unpack('<IQQ', b[:20])
            chunk = data[off:off + dlen]
            u.write(EP_OUT, chunk)
            sent += len(chunk)
            print(f'    64B_READ_DATA off=0x{off:x} len={dlen}')

        elif c in (0x04, 0x13):           # END_OF_IMAGE
            b = read_exact(u, l - 8, 4000)
            iid, st = struct.unpack('<II', b[:8]) if len(b) >= 8 else (0, 0)
            print(f'[+] END_OF_IMAGE image={iid} status={st}')
            send_done_variant(u, variant)
            print(f'[+] 已发 DONE (len={variant})')
            if st == 0:
                break

        elif c == 0x05:                   # DONE
            print('[+] 收到 DONE')
            u.write(EP_OUT, struct.pack('<II', 0x06, 8))
            print('[+] 已发 DONE_RESP')
            break

        elif c == 0x06:
            print('[+] 收到 DONE_RESP，Sahara 完成！')
            break

        else:
            print(f'[?] cmd=0x{c:x} ({name}) len={l}')
            if l > 8:
                read_exact(u, l - 8, 2000)

    print(f'[+] 共发送 {sent} 字节')
    u.close()


if __name__ == '__main__':
    main()