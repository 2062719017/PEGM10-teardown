import rawlibusb, struct, time, sys

def open_dev():
    u = rawlibusb.RawLibUSB()
    u.open(0x05c6, 0x9008, 0)
    return u


def read_pkt(u, timeout=3000):
    try:
        hdr = u.read(0x81, 8, timeout)
    except rawlibusb.LibUSBTimeout:
        return None, None
    if len(hdr) < 8:
        return None, None
    cmd, ln = struct.unpack('<II', hdr)
    body = b''
    if ln > 8:
        try:
            body = u.read(0x81, ln - 8, timeout)
        except rawlibusb.LibUSBTimeout:
            pass
    return cmd, (ln, body)


def reset_and_watch():
    u = open_dev()
    print('[+] 已打开')

    # 清空残留
    for _ in range(6):
        c, p = read_pkt(u, 400)
        if c is None:
            break
        print('[i] 残留 cmd=0x%x %s' % (c, p))

    print('[*] 发送 SAHARA_RESET(0x07)...')
    u.write(0x01, struct.pack('<II', 0x07, 8))

    print('[*] 观察 10 秒...')
    deadline = time.time() + 10
    while time.time() < deadline:
        c, p = read_pkt(u, 1500)
        if c is None:
            print('    (无数据)')
            continue
        ln, body = p
        name = {0x01:'HELLO',0x02:'HELLO_RESP',0x03:'READ_DATA',0x04:'END_OF_IMAGE',
                0x05:'DONE',0x06:'DONE_RESP',0x07:'RESET',0x08:'RESET_RESP'}.get(c, hex(c))
        print('    cmd=0x%x (%s) len=%d body=%s' % (c, name, ln, body[:24].hex()))
        if c == 0x01:
            print('[+] 收到 HELLO，设备已复位到初始状态')
            break
    u.close()


if __name__ == '__main__':
    reset_and_watch()