import rawlibusb, struct, time, sys

VID, PID, EP_IN, EP_OUT = 0x05C6, 0x9008, 0x81, 0x01

def open_dev():
    last = None
    for i in range(80):
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
            time.sleep(0.4)
    raise SystemExit(f'无法打开设备: {last}')


def raw_dump(u, label, timeout=1200, size=256):
    """读一段原始字节并打印 hex"""
    try:
        d = u.read(EP_IN, size, timeout)
        print(f'  [{label}] {len(d)}B: {d.hex()}')
        return d
    except rawlibusb.LibUSBTimeout:
        print(f'  [{label}] (timeout)')
        return b''
    except Exception as e:
        print(f'  [{label}] err {type(e).__name__}: {e}')
        return b''


def main():
    u = open_dev()
    print('[+] 设备已打开')

    # ---- 1. 读 HELLO ----
    print('[*] 读 HELLO ...')
    d = raw_dump(u, 'HELLO-HDR', timeout=3000)
    if len(d) < 8:
        print('[!] 没读到 HELLO')
        u.close()
        return
    cmd, ln = struct.unpack('<II', d[:8])
    print(f'    cmd=0x{cmd:x} len={ln}')
    if cmd != 0x01:
        print('[!] 不是 HELLO，直接 dump 后续数据观察')
        for i in range(3):
            raw_dump(u, f'extra{i}')
        u.close()
        return

    # 读完整 HELLO body
    body = b''
    want = ln - 8
    while len(body) < want:
        try:
            chunk = u.read(EP_IN, want - len(body), 2000)
            body += chunk
        except rawlibusb.LibUSBTimeout:
            print('[!] HELLO body 读取超时')
            break
    print(f'    HELLO body({len(body)}B): {body.hex()}')
    if len(body) >= 16:
        v, vmin, mp, mode = struct.unpack('<IIII', body[:16])
        print(f'    version={v} min={vmin} maxpkt={mp} mode={mode}')

    # ---- 2. 发 HELLO_RESP ----
    resp = struct.pack('<IIIIII6I', 0x02, 48, 2, 1, 1024, 0, 0, 0, 0, 0, 0, 0)
    n = u.write(EP_OUT, resp)
    print(f'[+] 已发 HELLO_RESP ({n}B)')

    # ---- 3. 纯原始 dump 后续字节流 ----
    print('[*] 原始 dump 后续字节流（不解析）:')
    for i in range(6):
        raw_dump(u, f'after{i}', timeout=1500, size=128)

    u.close()


if __name__ == '__main__':
    main()