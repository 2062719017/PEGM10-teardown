import ctypes
import struct
import sys
import time

import libusb_package

VID, PID, EP_IN, EP_OUT, IFACE = 0x05C6, 0x9008, 0x81, 0x01, 0

PROG = ('C:\\Users\\Qwistzz\\Downloads\\Compressed\\'
        'PEGM10domestic_11_13.1.0.2101CN01_2025061222420157'
        '\\IMAGES\\prog_firehose_ddr.elf')

NAMES = {
    0x01: 'HELLO', 0x02: 'HELLO_RESP', 0x03: 'READ_DATA', 0x04: 'END_OF_IMAGE',
    0x05: 'DONE', 0x06: 'DONE_RESP', 0x07: 'RESET', 0x08: 'RESET_RESP',
    0x09: 'MEMORY_DEBUG', 0x0A: 'MEMORY_READ', 0x0B: 'CMD_READY',
    0x0C: 'CMD_SWITCH_MODE', 0x0D: 'CMD_EXEC', 0x0E: 'CMD_EXEC_RESP',
    0x0F: 'CMD_EXEC_DATA', 0x12: '64B_READ_DATA', 0x13: '64B_END_OF_IMAGE',
}


class Usb:
    """常驻 libusb 上下文，冷启动后只需一次 init"""

    def __init__(self):
        self.lib = ctypes.CDLL(libusb_package.find_library('libusb-1.0'))
        L = self.lib
        L.libusb_init.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
        L.libusb_init.restype = ctypes.c_int
        L.libusb_exit.argtypes = [ctypes.c_void_p]
        L.libusb_open_device_with_vid_pid.argtypes = [
            ctypes.c_void_p, ctypes.c_uint16, ctypes.c_uint16]
        L.libusb_open_device_with_vid_pid.restype = ctypes.c_void_p
        L.libusb_close.argtypes = [ctypes.c_void_p]
        L.libusb_claim_interface.argtypes = [ctypes.c_void_p, ctypes.c_int]
        L.libusb_claim_interface.restype = ctypes.c_int
        L.libusb_release_interface.argtypes = [ctypes.c_void_p, ctypes.c_int]
        L.libusb_bulk_transfer.argtypes = [
            ctypes.c_void_p, ctypes.c_ubyte, ctypes.POINTER(ctypes.c_ubyte),
            ctypes.c_int, ctypes.POINTER(ctypes.c_int), ctypes.c_uint]
        L.libusb_bulk_transfer.restype = ctypes.c_int

        self.ctx = ctypes.c_void_p(None)
        r = L.libusb_init(ctypes.byref(self.ctx))
        if r != 0:
            raise RuntimeError(f'libusb_init 失败 {r}')
        self.handle = None

    def try_open(self):
        """尝试打开，成功返回 True"""
        h = self.lib.libusb_open_device_with_vid_pid(self.ctx, VID, PID)
        if not h:
            return False
        r = self.lib.libusb_claim_interface(h, IFACE)
        if r != 0:
            self.lib.libusb_close(h)
            return False
        self.handle = h
        return True

    def read(self, n, timeout_ms):
        buf = (ctypes.c_ubyte * n)()
        xfer = ctypes.c_int(0)
        r = self.lib.libusb_bulk_transfer(
            self.handle, EP_IN, buf, n, ctypes.byref(xfer),
            ctypes.c_uint(timeout_ms))
        if r == -7:
            raise TimeoutError('timeout')
        if r != 0:
            raise RuntimeError(f'bulk in err {r}')
        return bytes(buf[:xfer.value])

    def write(self, data, timeout_ms=5000):
        n = len(data)
        buf = (ctypes.c_ubyte * n).from_buffer_copy(data)
        xfer = ctypes.c_int(0)
        r = self.lib.libusb_bulk_transfer(
            self.handle, EP_OUT, buf, n, ctypes.byref(xfer),
            ctypes.c_uint(timeout_ms))
        if r != 0:
            raise RuntimeError(f'bulk out err {r}')
        return xfer.value

    def close_dev(self):
        if self.handle:
            try:
                self.lib.libusb_release_interface(self.handle, IFACE)
            except Exception:
                pass
            self.lib.libusb_close(self.handle)
            self.handle = None

    def shutdown(self):
        self.close_dev()
        if self.ctx:
            self.lib.libusb_exit(self.ctx)
            self.ctx = ctypes.c_void_p(None)


def read_exact(usb, n, timeout_ms):
    got = b''
    deadline = time.time() + timeout_ms / 1000.0
    while len(got) < n:
        remain = int(max(50, (deadline - time.time()) * 1000))
        try:
            c = usb.read(n - len(got), remain)
        except TimeoutError:
            break
        if not c:
            break
        got += c
    return got


def drain(usb, rounds=8):
    total = 0
    for _ in range(rounds):
        try:
            d = usb.read(256, 200)
            if not d:
                break
            total += len(d)
        except TimeoutError:
            break
        except Exception:
            break
    return total


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else 'wait'
    data = open(PROG, 'rb').read()
    usb = Usb()

    if mode == 'reset':
        # 尝试发 RESET 清状态
        if not usb.try_open():
            print('[!] 无法打开')
            return
        print('[+] 已打开，发 SAHARA_RESET')
        try:
            usb.write(struct.pack('<II', 0x07, 8))
            time.sleep(0.3)
            drain(usb)
        except Exception as e:
            print('[!]', e)
        usb.close_dev()
        print('[+] 已断开')
        usb.shutdown()
        return

    # 极速轮询等待设备
    print('[*] 极速轮询等待 EDL 设备出现（20ms 间隔，最长 180 秒）...')
    t0 = time.time()
    opened_at = None
    for i in range(9000):
        if usb.try_open():
            opened_at = time.time() - t0
            print(f'[+] 第 {i} 次轮询成功打开，耗时 {opened_at:.2f}s')
            break
        time.sleep(0.02)
    if not usb.handle:
        print('[!] 超时未等到设备')
        usb.shutdown()
        return

    # 打开后立即读 HELLO，不做任何其它操作
    print('[*] 立即读取数据 ...')
    hdr = read_exact(usb, 8, 3000)
    if len(hdr) < 8:
        print(f'[!] 首读不足 8 字节（{len(hdr)}B）: {hdr.hex()}')
        usb.close_dev()
        usb.shutdown()
        return

    cmd, ln = struct.unpack('<II', hdr)
    print(f'    RAW hdr = {hdr.hex()}')
    print(f'    cmd=0x{cmd:x} ({NAMES.get(cmd, "?")})  length={ln}')

    if cmd != 0x01:
        body = read_exact(usb, max(0, ln - 8), 2000)
        print(f'    body({len(body)}B) = {body.hex()}')
        usb.close_dev()
        usb.shutdown()
        return

    body = read_exact(usb, ln - 8, 2000)
    print(f'    HELLO body({len(body)}B) = {body.hex()}')
    if len(body) >= 16:
        v, vmin, mp, md = struct.unpack('<IIII', body[:16])
        print(f'    version={v} min={vmin} maxpkt={mp} mode={md}')

    # 立即回 HELLO_RESP（同一轮询窗口内）
    resp = struct.pack('<IIIIII6I', 0x02, 48, v, vmin, mp, md, 0, 0, 0, 0, 0, 0)
    usb.write(resp)
    print(f'[+] HELLO_RESP 已发 ({len(resp)}B)')

    # 立即读下一个包
    h2 = read_exact(usb, 8, 4000)
    if len(h2) < 8:
        print(f'[!] HELLO_RESP 后无响应')
    else:
        c2, l2 = struct.unpack('<II', h2)
        print(f'[<] cmd=0x{c2:x} ({NAMES.get(c2, "?")}) length={l2}')
        b2 = read_exact(usb, max(0, l2 - 8), 2000)
        print(f'    body = {b2.hex()}')
        if c2 == 0x03:
            iid, off, dlen = struct.unpack('<IQI', b2[:16])
            print(f'    ==> READ_DATA image={iid} offset=0x{off:x} len={dlen}')
            print('[+] 设备要求数据！Sahara 正常')

    usb.close_dev()
    usb.shutdown()


if __name__ == '__main__':
    main()