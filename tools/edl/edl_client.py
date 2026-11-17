#!/usr/bin/env python3
"""
edl_client.py — 纯 Python 的 Qualcomm EDL (9008) 客户端

实现两层协议：

  1) Sahara —— 把 firehose programmer 上传到设备
       设备主动发 SAHARA_READ_DATA(0x03) 索取指定偏移的数据，
       主机按需回填；设备发 SAHARA_END_OF_IMAGE(0x04) 表示收完，
       主机回 SAHARA_DONE(0x05)；随后设备切到 Firehose 模式。

  2) Firehose —— 用 XML 命令读写 eMMC/UFS 分区
       主机发 XML 字符串，设备回 XML（以 <response ... /> 结尾）。
       read 命令在 rawmode="true" 时，ACK 之后紧跟原始数据字节流。

依赖（均已在本地安装）：
    pyusb + libusb-package（自带 libusb-1.0.dll）
    Windows 侧需要把 05C6:9008 绑定到 WinUSB（Zadig）

用法：
    # 读 devinfo（LUN4 / sector 192522 / 1 个 sector）
    python edl_client.py --programmer fw/prog_firehose_ddr.elf \
           --read 4 192522 1 fw/devinfo_dump.bin

    # 只加载 programmer 并握手
    python edl_client.py --programmer fw/prog_firehose_ddr.elf --handshake
"""

import argparse
import struct
import sys
import time
import os

try:
    import usb.core
    import usb.util
    import usb.backend.libusb1
    import libusb_package
except ImportError as e:
    print(f"[!] 缺少依赖: {e}")
    sys.exit(1)

import ctypes

# ---------------------------------------------------------------------------
# 直连 libusb：Windows/WinUSB 后端下 get_configuration_descriptor 会抛
# NotImplementedError，导致 pyusb 无法构建端点表（read() 会 KeyError）。
# 因此读操作直接用 ctypes 调 libusb_bulk_transfer，绕开 pyusb 的端点映射。
# ---------------------------------------------------------------------------
class RawLibusb:
    def __init__(self):
        path = libusb_package.find_library()
        self.lib = ctypes.CDLL(path)
        self.lib.libusb_bulk_transfer.argtypes = [
            ctypes.c_void_p, ctypes.c_ubyte,
            ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int,
            ctypes.POINTER(ctypes.c_int), ctypes.c_uint]
        self.lib.libusb_bulk_transfer.restype = ctypes.c_int

    def bulk_read(self, handle, ep, size, timeout_ms):
        buf = (ctypes.c_ubyte * size)()
        xfer = ctypes.c_int(0)
        r = self.lib.libusb_bulk_transfer(
            ctypes.c_void_p(handle), ep, buf, size,
            ctypes.byref(xfer), ctypes.c_uint(timeout_ms))
        if r != 0:
            # -7 = LIBUSB_ERROR_TIMEOUT
            if r == -7:
                raise USBTimeout(r, size, xfer.value)
            raise RuntimeError(f"libusb_bulk_transfer 失败: {r}")
        return bytes(buf[:xfer.value])

    def bulk_write(self, handle, ep, data, timeout_ms):
        buf = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
        xfer = ctypes.c_int(0)
        r = self.lib.libusb_bulk_transfer(
            ctypes.c_void_p(handle), ep, buf, len(data),
            ctypes.byref(xfer), ctypes.c_uint(timeout_ms))
        if r != 0:
            raise RuntimeError(f"libusb_bulk_transfer(write) 失败: {r}")
        return xfer.value


class USBTimeout(Exception):
    def __init__(self, code, size, transferred):
        super().__init__(f"bulk read 超时 (code={code}, 请求 {size}B, 收到 {transferred}B)")
        self.transferred = transferred

VID = 0x05C6
PID = 0x9008

# Sahara 命令
SAHARA_HELLO = 0x01
SAHARA_HELLO_RESP = 0x02
SAHARA_READ_DATA = 0x03
SAHARA_END_OF_IMAGE = 0x04
SAHARA_DONE = 0x05
SAHARA_DONE_RESP = 0x06
SAHARA_RESET = 0x07
SAHARA_RESET_RESP = 0x08
SAHARA_MEMORY_DEBUG = 0x09
SAHARA_MEMORY_READ = 0x0A
SAHARA_CMD_READY = 0x0B
SAHARA_CMD_SWITCH_MODE = 0x0C
SAHARA_CMD_EXEC = 0x0D
SAHARA_CMD_EXEC_RESP = 0x0E
SAHARA_CMD_EXEC_DATA = 0x0F
SAHARA_64B_READ_DATA = 0x12
SAHARA_64B_END_OF_IMAGE = 0x13

SAHARA_NAMES = {
    0x01: 'HELLO', 0x02: 'HELLO_RESP', 0x03: 'READ_DATA', 0x04: 'END_OF_IMAGE',
    0x05: 'DONE', 0x06: 'DONE_RESP', 0x07: 'RESET', 0x08: 'RESET_RESP',
    0x09: 'MEMORY_DEBUG', 0x0A: 'MEMORY_READ', 0x0B: 'CMD_READY',
    0x0C: 'CMD_SWITCH_MODE', 0x0D: 'CMD_EXEC', 0x0E: 'CMD_EXEC_RESP',
    0x0F: 'CMD_EXEC_DATA', 0x12: '64B_READ_DATA', 0x13: '64B_END_OF_IMAGE',
}


def get_backend():
    return usb.backend.libusb1.get_backend(
        find_library=libusb_package.find_library)


class Edl:
    def __init__(self, timeout=10000):
        self.timeout = timeout
        self.dev = None
        self.ep_in = None
        self.ep_out = None
        self.cfg = None

    # ---------------- 设备发现 ----------------
    def find(self, retries=10, delay=2):
        be = get_backend()
        for i in range(retries):
            d = usb.core.find(idVendor=VID, idProduct=PID, backend=be)
            if d is not None:
                self.dev = d
                return True
            if i < retries - 1:
                print(f"    等待 EDL 设备出现... ({i+1}/{retries})")
                time.sleep(delay)
        return False

    def open(self):
        d = self.dev
        print(f"[*] 设备: bus={d.bus} addr={d.address} "
              f"idVendor=0x{d.idVendor:04x} idProduct=0x{d.idProduct:04x}")
        try:
            d.set_configuration()
        except usb.core.USBError:
            pass

        # Sahara 状态下部分设备对 GET_DESCRIPTOR 响应异常，
        # 因此不依赖 get_active_configuration，直接用已知端点。
        self.intf_num = 0
        self.ep_in_addr = 0x81
        self.ep_out_addr = 0x01

        try:
            cfg = d.get_active_configuration()
            intf = cfg[(0, 0)]
            self.intf_num = intf.bInterfaceNumber
            for ep in intf:
                if usb.util.endpoint_direction(ep.bEndpointAddress) == usb.util.ENDPOINT_IN:
                    self.ep_in_addr = ep.bEndpointAddress
                else:
                    self.ep_out_addr = ep.bEndpointAddress
            print(f"[+] 描述符枚举成功 接口={self.intf_num} "
                  f"IN=0x{self.ep_in_addr:02x} OUT=0x{self.ep_out_addr:02x}")
        except (usb.core.USBError, StopIteration) as e:
            print(f"[!] 描述符枚举失败({type(e).__name__})，使用默认端点 "
                  f"IN=0x{self.ep_in_addr:02x} OUT=0x{self.ep_out_addr:02x}")

        try:
            usb.util.claim_interface(d, self.intf_num)
            print("[+] 已 claim 接口")
        except usb.core.USBError as e:
            print(f"[!] claim_interface(pyusb): {e}，改用 ctypes 直接 claim")
            self.raw = RawLibusb()
            r = self.raw.lib.libusb_claim_interface(ctypes.c_void_p(self._handle()), self.intf_num)
            print(f"    libusb_claim_interface -> {r} ({'OK' if r == 0 else 'FAIL'})")
        if not hasattr(self, 'raw'):
            self.raw = RawLibusb()
        self.dev_handle = self._handle()
        print(f"[+] 底层 handle = 0x{self.dev_handle:x}")

    def _handle(self):
        """取 libusb device_handle 指针（pyusb 内部 _ctx.handle，需先 open）"""
        d = self.dev
        ctx = d._ctx
        if getattr(ctx, 'handle', None) is None:
            # 主动打开设备，pyusb 的 managed_open 会设置 ctx.handle
            try:
                ctx.managed_open()
            except Exception as e:
                print(f"[!] managed_open 失败: {e}")
        h = getattr(ctx, 'handle', None)
        if h is None:
            return 0
        return h if isinstance(h, int) else ctypes.cast(h, ctypes.c_void_p).value or 0

    # ---------------- 底层读写（全部走 ctypes） ----------------
    def read(self, size, timeout=None):
        return self.raw.bulk_read(self.dev_handle, self.ep_in_addr, size,
                                  timeout or self.timeout)

    def write(self, data, timeout=None):
        return self.raw.bulk_write(self.dev_handle, self.ep_out_addr, data,
                                   timeout or self.timeout)

    # ---------------- Sahara ----------------
    def sahara_handshake(self):
        print("[*] Sahara: 读取 HELLO ...")
        hdr = self.read(8)
        cmd, length = struct.unpack('<II', hdr)
        if cmd != SAHARA_HELLO:
            raise RuntimeError(f"预期的 HELLO，收到 0x{cmd:x} "
                               f"({SAHARA_NAMES.get(cmd,'?')})")
        rest = self.read(length - 8)
        version, version_min, max_packet, mode = struct.unpack('<IIII', rest[:16])
        print(f"[+] HELLO: version={version} min={version_min} "
              f"max_packet={max_packet} mode={mode}")
        if mode == 0:
            print("[+] 模式 = Image transfer (0)")
        else:
            print(f"[!] 模式 = {mode}（非 0，可能不是常规 EDL）")
        self.max_packet = max_packet

        # 回 HELLO_RESP（0x02, 48 字节）
        resp = struct.pack('<IIIIII6I',
                           SAHARA_HELLO_RESP, 48,
                           version, version_min,
                           max_packet, mode,
                           0, 0, 0, 0, 0, 0)
        self.write(resp)
        print("[+] 已回 HELLO_RESP")
        return mode

    def sahara_upload(self, programmer_path):
        data = open(programmer_path, 'rb').read()
        print(f"[*] programmer: {programmer_path} ({len(data)} bytes)")
        # 打开设备后先发 HELLO_REQ 是部分平台的约定；这里按 9008 常规流程直接等设备 HELLO
        self.sahara_handshake()

        total = 0
        retries = 0
        while True:
            try:
                hdr = self.read(8)
            except usb.core.USBError as e:
                print(f"[!] 读取失败: {e}")
                break
            cmd, length = struct.unpack('<II', hdr)
            name = SAHARA_NAMES.get(cmd, hex(cmd))

            if cmd == SAHARA_READ_DATA:
                body = self.read(length - 8)
                image_id, offset, dlen = struct.unpack('<IQI', body[:16])
                chunk = data[offset:offset + dlen]
                if len(chunk) < dlen:
                    print(f"[!] 请求越界: off=0x{offset:x} len={dlen} "
                          f"(文件 {len(data)} 字节)")
                    chunk = chunk.ljust(dlen, b'\x00')
                self.write(chunk)
                total += len(chunk)
                print(f"    READ_DATA image={image_id} off=0x{offset:08x} "
                      f"len={dlen} (累计 {total}/{len(data)})")

            elif cmd == SAHARA_64B_READ_DATA:
                body = self.read(length - 8)
                image_id, offset, dlen = struct.unpack('<IQQ', body[:20])
                chunk = data[offset:offset + dlen]
                self.write(chunk)
                total += len(chunk)
                print(f"    64B_READ_DATA off=0x{offset:x} len={dlen}")

            elif cmd in (SAHARA_END_OF_IMAGE, SAHARA_64B_END_OF_IMAGE):
                body = self.read(length - 8)
                if len(body) >= 8:
                    image_id, status = struct.unpack('<II', body[:8])
                else:
                    image_id, status = 0, 0
                print(f"[+] END_OF_IMAGE image={image_id} status={status}")
                # 回 DONE
                self.write(struct.pack('<II', SAHARA_DONE, 8))
                print("[+] 已发送 DONE")

            elif cmd == SAHARA_DONE:
                print("[+] SAHARA_DONE：programmer 传输完成")
                break

            elif cmd == SAHARA_RESET_RESP:
                print("[+] RESET_RESP")
                break

            else:
                print(f"[?] 未知命令 0x{cmd:x} ({name}) length={length}")
                if length > 8:
                    self.read(length - 8)
                retries += 1
                if retries > 20:
                    raise RuntimeError("Sahara 循环异常，退出")

        print(f"[+] Sahara 阶段结束，共上传 {total} 字节")
        time.sleep(1)

    # ---------------- Firehose ----------------
    def firehose_configure(self, memory_name="ufs", max_payload=1048576):
        xml = (f'<configure MemoryName="{memory_name}" Verbose="0" '
               f'AlwaysValidate="0" MaxDigestTableSizeInBytes="2048" '
               f'MaxPayloadSizeToTargetInBytes="{max_payload}" '
               f'ZlpAwareHost="1" SkipStorageInit="0" />')
        return self.firehose_cmd(xml)

    def _read_until_response(self):
        """读取直到收到 <response ...> 元素，返回 (response_xml, raw_after)"""
        buf = b''
        deadline = time.time() + 30
        while time.time() < deadline:
            try:
                chunk = self.read(self.max_packet or 4096, timeout=5000)
            except usb.core.USBError:
                continue
            if not chunk:
                continue
            buf += chunk
            if b'<response' in buf and b'/>' in buf.split(b'<response', 1)[1]:
                return buf
        raise RuntimeError(f"未收到 response（已收 {len(buf)} 字节）: {buf[:200]!r}")

    def firehose_cmd(self, xml):
        print(f"[>] {xml[:160]}{'...' if len(xml) > 160 else ''}")
        self.write(xml.encode('utf-8'))
        resp = self._read_until_response()
        text = resp.decode('utf-8', 'replace')
        print(f"[<] {text[:400]}")
        return text

    def read_partition(self, lun, start_sector, num_sectors,
                       out_path, sector_size=4096):
        xml = (f'<read SECTOR_SIZE_IN_BYTES="{sector_size}" '
               f'num_partition_sectors="{num_sectors}" '
               f'physical_partition_number="{lun}" '
               f'start_sector="{start_sector}" />')
        self.write(xml.encode('utf-8'))
        resp = self._read_until_response()
        text = resp.decode('utf-8', 'replace')
        print(f"[<] {text[:300]}")

        if 'ACK' not in text:
            print("[!] 未收到 ACK，放弃读取数据")
            return False

        need = num_sectors * sector_size
        got = b''
        print(f"[*] 等待 {need} 字节数据 ...")
        deadline = time.time() + 60
        while len(got) < need and time.time() < deadline:
            try:
                chunk = self.read(min(1048576, need - len(got)), timeout=10000)
            except usb.core.USBError as e:
                print(f"    读取超时: {e}")
                break
            if not chunk:
                break
            got += chunk
            print(f"    已收 {len(got)}/{need}")

        if not got:
            print("[!] 没有收到数据")
            return False

        open(out_path, 'wb').write(got)
        print(f"[+] 写入 {out_path} ({len(got)} 字节)")
        return True

    def close(self):
        if self.dev:
            try:
                usb.util.release_interface(self.dev, self.intf_num)
            except Exception:
                pass
            try:
                usb.util.dispose_resources(self.dev)
            except Exception:
                pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--programmer', required=True, help='prog_firehose_ddr.elf 路径')
    ap.add_argument('--read', nargs=3, metavar=('LUN', 'START', 'COUNT'),
                    help='读取分区：LUN 起始扇区 扇区数')
    ap.add_argument('--out', default='dump.bin')
    ap.add_argument('--handshake', action='store_true', help='只做 Sahara 握手')
    ap.add_argument('--memory', default='ufs', choices=['ufs', 'emmc'])
    args = ap.parse_args()

    if not os.path.exists(args.programmer):
        print(f"[!] programmer 不存在: {args.programmer}")
        sys.exit(1)

    e = Edl()
    print("[*] 查找 EDL 设备 (05c6:9008) ...")
    if not e.find():
        print("[!] 未找到 EDL 设备")
        print("    检查：1) 手机是否在 EDL 模式  2) 驱动是否已绑到 WinUSB（Zadig）")
        sys.exit(1)

    e.open()
    try:
        if args.handshake:
            e.sahara_handshake()
            return

        e.sahara_upload(args.programmer)

        # Sahara 之后设备会重新枚举，重新查找并打开
        print("[*] programmer 已加载，重新查找设备 ...")
        time.sleep(3)
        e.close()
        e2 = Edl()
        if not e2.find(retries=15):
            print("[!] Firehose 模式下未找到设备")
            sys.exit(1)
        e2.open()
        try:
            e2.firehose_configure(args.memory)
            if args.read:
                lun = int(args.read[0])
                start = int(args.read[1])
                count = int(args.read[2])
                e2.read_partition(lun, start, count, args.out)
        finally:
            e2.close()
    finally:
        e.close()


if __name__ == '__main__':
    main()
