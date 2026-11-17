import rawlibusb, struct, time, sys

XML_CONFIGURE = ('<configure MemoryName="ufs" Verbose="0" AlwaysValidate="0" '
                 'MaxDigestTableSizeInBytes="2048" '
                 'MaxPayloadSizeToTargetInBytes="1048576" '
                 'ZlpAwareHost="1" SkipStorageInit="0" />')

READ_DEVINFO = ('<read SECTOR_SIZE_IN_BYTES="4096" num_partition_sectors="1" '
                'physical_partition_number="4" start_sector="192522" />')


def open_dev():
    u = rawlibusb.RawLibUSB()
    u.open(0x05c6, 0x9008, 0)
    return u


def try_read(u, timeout=3000, n=2048):
    try:
        return u.read(0x81, n, timeout)
    except rawlibusb.LibUSBTimeout:
        return b''
    except Exception as e:
        print('  read err', type(e).__name__, e)
        return b''


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else 'probe'
    u = open_dev()
    print('[+] 设备已打开')

    # 先看有没有遗留数据
    d = try_read(u, 500, 2048)
    if d:
        print('[i] 遗留数据 %d 字节: %s' % (len(d), d[:64].hex()))
        try:
            cmd, ln = struct.unpack('<II', d[:8])
            print('    cmd=0x%x len=%d' % (cmd, ln))
        except Exception:
            pass

    if mode == 'probe':
        print('[i] 探测模式：不发任何东西')
    else:
        xml = XML_CONFIGURE if mode == 'configure' else READ_DEVINFO
        n = u.write(0x01, xml.encode())
        print('[+] 已发 %d 字节: %s' % (n, mode))

        deadline = time.time() + 8
        got = b''
        while time.time() < deadline:
            chunk = try_read(u, 1500, 2048)
            if chunk:
                got += chunk
                print('    +%d 字节 (累计 %d)' % (len(chunk), len(got)))
                if b'<response' in got or b'<log' in got:
                    break
            else:
                break
        if got:
            print('[<] %s' % got[:300])
        else:
            print('[!] 无响应')

    u.close()


if __name__ == '__main__':
    main()