#!/usr/bin/env python3
"""
rawlibusb.py — 纯 ctypes 的 libusb 封装（绕开 pyusb 在 Windows 上的描述符 bug）

pyusb 1.3.1 + libusb-package 在 Windows/WinUSB 下：
    d.get_active_configuration() -> NotImplementedError
    d._ctx.managed_open()        -> NotImplementedError
原因是这些路径都要读 configuration descriptor，而 WinUSB 后端未实现。
结果是拿不到 device_handle，任何 bulk 传输都无法进行。

本模块直接用 ctypes 调 libusb-1.0 的原生 API，不经过 pyusb 的描述符层：

    libusb_init
    libusb_open_device_with_vid_pid
    libusb_claim_interface
    libusb_bulk_transfer
    libusb_close / libusb_exit

端点地址按 EDL 9008 的固定布局硬编码：IN=0x81, OUT=0x01, interface=0。
"""

import ctypes
import ctypes.util


class LibUSBError(Exception):
    pass


class LibUSBTimeout(LibUSBError):
    def __init__(self, transferred, requested):
        super().__init__(f"bulk 传输超时（请求 {requested} 字节，收到 {transferred}）")
        self.transferred = transferred


# libusb error codes
LIBUSB_SUCCESS = 0
LIBUSB_ERROR_TIMEOUT = -7
LIBUSB_ERROR_NO_DEVICE = -4
LIBUSB_ERROR_NOT_FOUND = -5
LIBUSB_ERROR_BUSY = -6
LIBUSB_ERROR_NOT_SUPPORTED = -12
LIBUSB_ERROR_ACCESS = -3

ERR_NAMES = {
    0: 'SUCCESS', -1: 'IO', -2: 'INVALID_PARAM', -3: 'ACCESS', -4: 'NO_DEVICE',
    -5: 'NOT_FOUND', -6: 'BUSY', -7: 'TIMEOUT', -8: 'OVERFLOW',
    -9: 'PIPE', -10: 'INTERRUPTED', -11: 'NO_MEM', -12: 'NOT_SUPPORTED',
    -99: 'OTHER',
}


def _load():
    """按优先级尝试若干 libusb DLL 名称"""
    candidates = []
    try:
        import libusb_package
        for cand in ('libusb-1.0', 'libusb-1.0.dll', 'usb-1.0'):
            try:
                p = libusb_package.find_library(cand)
                if p:
                    candidates.append(p)
            except Exception:
                pass
    except Exception:
        pass
    for name in ('libusb-1.0.dll', 'libusb-1.0'):
        candidates.append(name)
    found = ctypes.util.find_library('usb-1.0')
    if found:
        candidates.append(found)

    last = None
    tried = []
    for c in candidates:
        tried.append(str(c))
        try:
            return ctypes.CDLL(c)
        except OSError as e:
            last = e
    raise LibUSBError(f"无法加载 libusb: {last}\n  已尝试: {tried}")


class RawLibUSB:
    def __init__(self):
        self.lib = _load()
        L = self.lib

        L.libusb_init.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
        L.libusb_init.restype = ctypes.c_int

        L.libusb_exit.argtypes = [ctypes.c_void_p]
        L.libusb_exit.restype = None

        L.libusb_open_device_with_vid_pid.argtypes = [
            ctypes.c_void_p, ctypes.c_uint16, ctypes.c_uint16]
        L.libusb_open_device_with_vid_pid.restype = ctypes.c_void_p

        L.libusb_close.argtypes = [ctypes.c_void_p]
        L.libusb_close.restype = None

        L.libusb_claim_interface.argtypes = [ctypes.c_void_p, ctypes.c_int]
        L.libusb_claim_interface.restype = ctypes.c_int

        L.libusb_release_interface.argtypes = [ctypes.c_void_p, ctypes.c_int]
        L.libusb_release_interface.restype = ctypes.c_int

        L.libusb_set_configuration.argtypes = [ctypes.c_void_p, ctypes.c_int]
        L.libusb_set_configuration.restype = ctypes.c_int

        L.libusb_bulk_transfer.argtypes = [
            ctypes.c_void_p, ctypes.c_ubyte,
            ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int,
            ctypes.POINTER(ctypes.c_int), ctypes.c_uint]
        L.libusb_bulk_transfer.restype = ctypes.c_int

        L.libusb_get_string_descriptor_ascii.argtypes = [
            ctypes.c_void_p, ctypes.c_ubyte,
            ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int]
        L.libusb_get_string_descriptor_ascii.restype = ctypes.c_int

        self.ctx = ctypes.c_void_p(None)
        r = L.libusb_init(ctypes.byref(self.ctx))
        if r != 0:
            raise LibUSBError(f"libusb_init 失败: {r}")

        self.handle = None
        self.claimed = False

    # ------------------------------------------------------------------
    def open(self, vid, pid, interface=0, reset_config=True):
        h = self.lib.libusb_open_device_with_vid_pid(self.ctx, vid, pid)
        if not h:
            raise LibUSBError(f"找不到或无法打开设备 {vid:04x}:{pid:04x}")
        self.handle = h

        if reset_config:
            r = self.lib.libusb_set_configuration(h, 1)
            # 已经是配置 1 时可能返回 BUSY/NOT_SUPPORTED，忽略
            if r not in (0, LIBUSB_ERROR_BUSY, LIBUSB_ERROR_NOT_SUPPORTED):
                print(f"    set_configuration(1) -> {ERR_NAMES.get(r, r)}")

        r = self.lib.libusb_claim_interface(h, interface)
        if r != 0:
            raise LibUSBError(
                f"claim_interface({interface}) 失败: {ERR_NAMES.get(r, r)}")
        self.claimed = True
        self.interface = interface
        print(f"[+] libusb handle=0x{h:x}  interface={interface} 已 claim")

    def read(self, ep, size, timeout_ms=10000):
        buf = (ctypes.c_ubyte * size)()
        xfer = ctypes.c_int(0)
        r = self.lib.libusb_bulk_transfer(
            self.handle, ep, buf, size, ctypes.byref(xfer),
            ctypes.c_uint(timeout_ms))
        if r == LIBUSB_ERROR_TIMEOUT:
            raise LibUSBTimeout(xfer.value, size)
        if r != 0:
            raise LibUSBError(f"bulk IN 失败: {ERR_NAMES.get(r, r)} (收到 {xfer.value}B)")
        return bytes(buf[:xfer.value])

    def write(self, ep, data, timeout_ms=10000):
        n = len(data)
        if n == 0:
            return 0
        buf = (ctypes.c_ubyte * n).from_buffer_copy(data)
        xfer = ctypes.c_int(0)
        r = self.lib.libusb_bulk_transfer(
            self.handle, ep, buf, n, ctypes.byref(xfer),
            ctypes.c_uint(timeout_ms))
        if r != 0:
            raise LibUSBError(f"bulk OUT 失败: {ERR_NAMES.get(r, r)}")
        return xfer.value

    def close(self):
        if self.handle:
            if self.claimed:
                self.lib.libusb_release_interface(self.handle, self.interface)
                self.claimed = False
            self.lib.libusb_close(self.handle)
            self.handle = None
        if self.ctx:
            self.lib.libusb_exit(self.ctx)
            self.ctx = ctypes.c_void_p(None)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


if __name__ == '__main__':
    dev = RawLibUSB()
    try:
        dev.open(0x05c6, 0x9008)
        print("[+] 打开成功，试着读 8 字节（Sahara 头）...")
        try:
            d = dev.read(0x81, 8, 3000)
            print(f"    {len(d)} 字节: {d.hex()}")
        except LibUSBTimeout as e:
            print(f"    超时: {e}")
    finally:
        dev.close()
