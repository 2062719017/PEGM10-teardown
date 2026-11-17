import rawlibusb, struct, time

def try_once():
    u = None
    try:
        u = rawlibusb.RawLibUSB()
        u.open(0x05c6, 0x9008, 0)
        return u, 'OK'
    except Exception as e:
        if u:
            try:
                u.close()
            except Exception:
                pass
        return None, f'{type(e).__name__}: {e}'


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


NAMES = {0x01: 'HELLO', 0x02: 'HELLO_RESP', 0x03: 'READ_DATA',
         0x04: 'END_OF_IMAGE', 0x05: 'DONE', 0x06: 'DONE_RESP',
         0x07: 'RESET', 0x08: 'RESET_RESP'}

# 等设备可 claim
u = None
for i in range(60):
    u, st = try_once()
    if u:
        print('[+] 第 %d 次尝试成功打开' % (i + 1))
        break
    if i % 10 == 0:
        print('    [%d] %s' % (i, st))
    time.sleep(0.5)

if not u:
    print('[!] 无法打开设备')
    raise SystemExit(1)

# 读 HELLO
print('[*] 读取 Sahara 数据 ...')
deadline = time.time() + 12
got_hello = False
while time.time() < deadline:
    c, p = read_pkt(u, 2000)
    if c is None:
        print('    (无数据)')
        continue
    ln, body = p
    print('    cmd=0x%x (%s) len=%d body=%s' %
          (c, NAMES.get(c, '?'), ln, body[:32].hex()))
    if c == 0x01:
        got_hello = True
        break

if got_hello:
    print('[+] 收到 HELLO！可以开始上传 programmer')
else:
    print('[-] 没有 HELLO。设备可能已经过了这个阶段。')

u.close()