#!/usr/bin/env python3
"""
edl.py — Qualcomm EDL (9008) 客户端 v2：纯 ctypes/libibusb 实现

背景：
  pyusb 1.3.1 + libusb-package 在 Windows/WinUSB 下会在
  get_active_configuration() / _ctx.managed_open() 抛 NotImplementedError，
  导致拿不到 device_handle，无法进行任何 bulk 传输。

  因此本实现完全绕开 pyusb，直接 ctypes 调 libusb-1.0：
      libusb_init / libusb_open / libusb_claim_interface / libusb_bulk_transfer

协议：
  1) Sahara —— 把 firehose programmer 上传到设备
       设备发 HELLO(0x01) -> 主机回 HELLO_RESP(0x02)
       设备发 READ_DATA(0x03)/64B_READ_DATA(0x12) 索取数据 -> 主机回填
       设备发 END_OF_IMAGE(0x04) -> 主机回 DONE(0x05)
  2) Firehose —— XML 命令读写分区

用法：
    python edl.py --programmer prog_firehose_ddr.elf --handshake
    python edl.py --programmer prog_firehose_ddr.elf --read 4 192522 1 --out devinfo.bin
"""

import argparse
import os
import struct
import sys
import time

from rawlibusb import RawLibUSB, LibUSBError, LibUSBTimeout

VID = 0x05C6
PID = 0x9008
EP_IN = 0x81
EP_OUT = 0x01
INTERFACE = 0

SAHARA_HELLO = 0x01
SAHARA_HELLO_RESP = 0x02
SAHARA_READ_DATA = 0x03
SAHARA_END_OF_IMAGE = 0x04
SAHARA_DONE = 0x05
SAHARA_DONE_RESP = 0x06
SAHARA_RESET = 0x07
SAHARA_RESET_RESP = 0x08
SAHARA_64B_READ_DATA = 0x12
SAHARA_64B_END_OF_IMAGE = 0x13

CMD_NAMES = {
    0x01: 'HELLO', 0x02: 'HELLO_RESP', 0x03: 'READ_DATA', 0x04: 'END_OF_IMAGE',
    0x05: 'DONE', 0x06: 'DONE_RESP', 0x07: 'RESET', 0x08: 'RESET_RESP',
    0x09: 'MEMORY_DEBUG', 0x0A: 'MEMORY_READ', 0x0B: 'CMD_READY',
    0x0C: 'CMD_SWITCH_MODE', 0x0D: 'CMD_EXEC', 0x0E: 'CMD_EXEC_RESP',
    0x0F: 'CMD_EXEC_DATA', 0x12: '64B_READ_DATA', 0x13: '64B_END_OF_IMAGE',
}


class Edl:
    def __init__(self, timeout_ms=10000):
        self.timeout = timeout_ms
        self.usb = None
        self.max_packet = 1024

    # ------------------------------------------------------------------
    def connect(self, retries=120, delay=0.5):
        """持续轮询直到设备可打开。
        EDL 在设备枚举后有短暂窗口，Windows 绑定 WinUSB 也需要几秒，
        因此每次重试都重建 libusb 上下文，确保拿到最新句柄。"""
        for i in range(retries):
            try:
                u = RawLibUSB()
                u.open(VID, PID, INTERFACE)
                self.usb = u
                if i > 0:
                    print(f"[+] 第 {i+1} 次尝试成功")
                return True
            except LibUSBError as e:
                # 关闭上一次可能残留的上下文
                try:
                    u.close()
                except Exception:
                    pass
                if i == 0:
                    print(f"[!] 首轮打开失败: {e}")
                    print("    （设备可能在枚举中，继续轮询）")
                if i % 10 == 9:
                    print(f"    ...已等待 {int((i+1)*delay)} 秒")
                time.sleep(delay)
        return False

    def read(self, n, timeout=None):
        return self.usb.read(EP_IN, n, timeout or self.timeout)

    def write(self, data, timeout=None):
        return self.usb.write(EP_OUT, data, timeout or self.timeout)

    def drain(self, rounds=8, timeout=300):
        """清空接收缓冲里的残留数据"""
        total = 0
        for _ in range(rounds):
            try:
                d = self.read(512, timeout=timeout)
                if not d:
                    break
                total += len(d)
            except LibUSBTimeout:
                break
            except LibUSBError:
                break
        if total:
            print(f"[*] 清掉残留 {total} 字节")

    # ------------------------------------------------------------------
    def sahara_hello(self, expect=True):
        print("[*] Sahara: 读取 HELLO ...")
        hdr = self.read(8)
        cmd, length = struct.unpack('<II', hdr)
        if cmd != SAHARA_HELLO:
            raise RuntimeError(
                f"预期 HELLO(0x01)，收到 0x{cmd:x} ({CMD_NAMES.get(cmd, '?')})")
        body = self.read(length - 8)
        version, version_min, max_packet, mode = struct.unpack('<IIII', body[:16])
        print(f"[+] HELLO version={version} min={version_min} "
              f"max_packet={max_packet} mode={mode}")
        self.max_packet = max_packet or 1024

        resp = struct.pack('<IIIIII6I', SAHARA_HELLO_RESP, 48,
                           version, version_min, self.max_packet, mode,
                           0, 0, 0, 0, 0, 0)
        self.write(resp)
        print("[+] 已回 HELLO_RESP")
        return mode

    def sahara_upload(self, path):
        data = open(path, 'rb').read()
        print(f"[*] programmer: {os.path.basename(path)} ({len(data)} 字节)")

        self.sahara_hello()

        sent = 0
        guard = 0
        while True:
            guard += 1
            if guard > 5000:
                raise RuntimeError("Sahara 循环次数异常")
            hdr = self.read(8)
            cmd, length = struct.unpack('<II', hdr)

            if cmd == SAHARA_READ_DATA:
                body = self.read(length - 8)
                image_id, offset, dlen = struct.unpack('<IQI', body[:16])
                chunk = data[offset:offset + dlen]
                if len(chunk) < dlen:
                    print(f"[!] 越界请求 off=0x{offset:x} len={dlen}，补零")
                    chunk = chunk + b'\x00' * (dlen - len(chunk))
                self.write(chunk)
                sent += len(chunk)
                if sent % (256 * 1024) < len(chunk) or sent == len(data):
                    print(f"    READ_DATA off=0x{offset:07x} len={dlen:6d} "
                          f"| {sent}/{len(data)} ({100*sent//max(1,len(data))}%)")

            elif cmd == SAHARA_64B_READ_DATA:
                body = self.read(length - 8)
                image_id, offset, dlen = struct.unpack('<IQQ', body[:20])
                chunk = data[offset:offset + dlen]
                self.write(chunk)
                sent += len(chunk)

            elif cmd in (SAHARA_END_OF_IMAGE, SAHARA_64B_END_OF_IMAGE):
                body = self.read(length - 8)
                image_id, status = (struct.unpack('<II', body[:8])
                                    if len(body) >= 8 else (0, 0))
                print(f"[+] END_OF_IMAGE image={image_id} status={status}")
                self.write(struct.pack('<II', SAHARA_DONE, 8))
                print("[+] 已发 DONE")

            elif cmd == SAHARA_DONE:
                print("[+] SAHARA_DONE：programmer 传输完成")
                break

            elif cmd == SAHARA_RESET_RESP:
                print("[!] 收到 RESET_RESP（设备已复位，需要重新开始）")
                break

            else:
                print(f"[?] 未知命令 0x{cmd:x} ({CMD_NAMES.get(cmd,'?')}) len={length}")
                if length > 8:
                    self.read(length - 8)

        print(f"[+] Sahara 结束，共发送 {sent} 字节")
        return sent

    # ------------------------------------------------------------------
    def fh_wait_response(self, timeout_s=30):
        buf = b''
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            try:
                chunk = self.read(self.max_packet, timeout=4000)
            except LibUSBTimeout:
                continue
            except LibUSBError as e:
                raise RuntimeError(f"Firehose 读取失败: {e}")
            if not chunk:
                continue
            buf += chunk
            if b'<response' in buf:
                tail = buf.split(b'<response', 1)[1]
                if b'/>' in tail:
                    return buf
        raise RuntimeError(f"等待 response 超时，已收 {len(buf)} 字节: {buf[:200]!r}")

    def fh_cmd(self, xml):
        print(f"[>] {xml[:150]}{'...' if len(xml) > 150 else ''}")
        self.write(xml.encode('utf-8'))
        resp = self.fh_wait_response()
        text = resp.decode('utf-8', 'replace')
        print(f"[<] {text[:400]}")
        return text, resp

    def configure(self, memory='ufs', max_payload=1048576):
        xml = (f'<configure MemoryName="{memory}" Verbose="0" '
               f'AlwaysValidate="0" MaxDigestTableSizeInBytes="2048" '
               f'MaxPayloadSizeToTargetInBytes="{max_payload}" '
               f'ZlpAwareHost="1" SkipStorageInit="0" />')
        return self.fh_cmd(xml)

    def read_partition(self, lun, start, count, out_path, sector_size=4096):
        xml = (f'<read SECTOR_SIZE_IN_BYTES="{sector_size}" '
               f'num_partition_sectors="{count}" '
               f'physical_partition_number="{lun}" '
               f'start_sector="{start}" />')
        text, raw = self.fh_cmd(xml)

        if 'ACK' not in text:
            print("[!] 未收到 ACK")
            return None

        # ACK 之后可能已经带了一部分数据（同一包内）
        need = count * sector_size
        got = b''
        if b'/>' in raw:
            tail = raw.split(b'/>', 1)[1]
            # 去掉换行/回车后若还有内容，视为数据起始
            tail = tail.lstrip(b'\r\n')
            if tail:
                got = tail

        print(f"[*] 需要 {need} 字节，已随 ACK 收到 {len(got)} 字节")
        deadline = time.time() + 60
        while len(got) < need and time.time() < deadline:
            try:
                chunk = self.read(min(1048576, need - len(got)), timeout=10000)
            except LibUSBTimeout:
                print("    读取超时，停止")
                break
            except LibUSBError as e:
                print(f"    读取失败: {e}")
                break
            if not chunk:
                break
            got += chunk

        if not got:
            print("[!] 没有收到数据")
            return None

        open(out_path, 'wb').write(got)
        print(f"[+] 已保存 {out_path} ({len(got)} 字节)")
        return got

    def close(self):
        if self.usb:
            self.usb.close()
            self.usb = None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--programmer', required=True)
    ap.add_argument('--read', nargs=3, metavar=('LUN', 'START', 'COUNT'))
    ap.add_argument('--out', default='dump.bin')
    ap.add_argument('--handshake', action='store_true')
    ap.add_argument('--memory', default='ufs', choices=['ufs', 'emmc'])
    ap.add_argument('--no-configure', action='store_true')
    args = ap.parse_args()

    if not os.path.exists(args.programmer):
        print(f"[!] programmer 不存在: {args.programmer}")
        sys.exit(1)

    e = Edl()
    print("[*] 连接 EDL 设备 (05c6:9008) ...")
    if not e.connect():
        print("[!] 无法打开设备")
        print("    1) 手机是否在 EDL 模式（adb reboot edl）")
        print("    2) 驱动是否为 WinUSB（Zadig）")
        print("    3) 设备管理器里是否有黄色感叹号")
        sys.exit(1)

    try:
        # 注意：这里绝不能 drain —— Sahara HELLO 包正好 48 字节，
        # 会被当成"残留"清掉，导致 sahara_hello() 读不到数据。

        if args.handshake:
            e.sahara_hello()
            print("[+] 握手测试完成")
            return

        e.sahara_upload(args.programmer)

        print("[*] 等待设备切到 Firehose 模式 ...")
        time.sleep(2)
        e.close()

        e2 = Edl()
        if not e2.connect(retries=30, delay=1):
            print("[!] Firehose 模式下未找到设备")
            sys.exit(2)
        try:
            if not args.no_configure:
                e2.configure(args.memory)
            if args.read:
                lun, start, count = (int(x) for x in args.read)
                e2.read_partition(lun, start, count, args.out)
        finally:
            e2.close()
    finally:
        e.close()


if __name__ == '__main__':
    main()
