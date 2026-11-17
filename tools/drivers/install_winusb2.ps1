# install_winusb2.ps1 — 用 SetupDiSetDeviceInstallParams 限定 DriverPath 后强制安装 WinUSB
#
# 与 force_winusb.ps1 的区别：
#   之前漏了 SetupDiSetDeviceInstallParams(DriverPath=<winusb.inf>)，
#   导致 SetupDiBuildDriverInfoList 枚举的是"该设备所属类的全部驱动"，
#   于是选中了毫不相干的驱动。
#   本脚本先把 DriverPath 限定到 C:\Windows\INF\winusb.inf，再枚举并安装。

param(
    [string]$HardwareId = "USB\VID_05C6&PID_9008",
    [string]$InfPath = "$env:WINDIR\INF\winusb.inf"
)

$ErrorActionPreference = "Stop"

$cs = @'
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class SuApi
{
    [StructLayout(LayoutKind.Sequential)]
    public struct SP_DEVINFO_DATA
    {
        public int cbSize;
        public Guid ClassGuid;
        public int DevInst;
        public IntPtr Reserved;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct SP_DRVINFO_DATA
    {
        public int cbSize;
        public int DriverType;
        public IntPtr Reserved;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string Description;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string MfgName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string ProviderName;
        public long DriverDate;
        public long DriverVersion;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct SP_DEVINSTALL_PARAMS
    {
        public int cbSize;
        public int Flags;
        public int FlagsEx;
        public IntPtr hwndParent;
        public IntPtr InstallMsgHandler;
        public IntPtr InstallMsgHandlerContext;
        public IntPtr FileQueue;
        public IntPtr ClassInstallReserved;
        public int Reserved;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string DriverPath;
    }

    public const int DIGCF_PRESENT = 0x2;
    public const int DIGCF_ALLCLASSES = 0x4;
    public const int SPDIT_CLASSDRIVER = 0x1;
    public const int SPDIT_COMPATDRIVER = 0x2;
    public const int INSTALLFLAG_FORCE = 0x1;
    public const int INSTALLFLAG_NONINTERACTIVE = 0x4;

    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr SetupDiGetClassDevs(IntPtr ClassGuid, string Enumerator,
        IntPtr hwndParent, int Flags);

    [DllImport("setupapi.dll", SetLastError = true)]
    public static extern bool SetupDiEnumDeviceInfo(IntPtr set, int idx, ref SP_DEVINFO_DATA data);

    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool SetupDiGetDeviceInstanceId(IntPtr set, ref SP_DEVINFO_DATA data,
        StringBuilder id, int size, out int required);

    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool SetupDiSetSelectedDevice(IntPtr set, ref SP_DEVINFO_DATA data);

    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool SetupDiGetDeviceInstallParams(IntPtr set, ref SP_DEVINFO_DATA data,
        ref SP_DEVINSTALL_PARAMS p);

    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool SetupDiSetDeviceInstallParams(IntPtr set, ref SP_DEVINFO_DATA data,
        ref SP_DEVINSTALL_PARAMS p);

    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool SetupDiBuildDriverInfoList(IntPtr set, ref SP_DEVINFO_DATA data, int type);

    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool SetupDiEnumDriverInfo(IntPtr set, ref SP_DEVINFO_DATA data,
        int type, int idx, ref SP_DRVINFO_DATA drv);

    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool SetupDiSetSelectedDriver(IntPtr set, ref SP_DEVINFO_DATA data,
        ref SP_DRVINFO_DATA drv);

    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool SetupDiDestroyDeviceInfoList(IntPtr set);

    [DllImport("newdev.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool DiInstallDevice(IntPtr hwnd, IntPtr set, ref SP_DEVINFO_DATA data,
        ref SP_DRVINFO_DATA drv, int flags, out bool needReboot);

    public static int LastErr { get { return Marshal.GetLastWin32Error(); } }
    public static int SizeOf<T>() { return Marshal.SizeOf(typeof(T)); }
}
'@

Add-Type -TypeDefinition $cs -Language CSharp

Write-Host "[*] 硬件 ID : $HardwareId"
Write-Host "[*] 驱动 INF: $InfPath"
if (-not (Test-Path $InfPath)) { Write-Host "[!] INF 不存在" -ForegroundColor Red; exit 1 }

$set = [SuApi]::SetupDiGetClassDevs([IntPtr]::Zero, "USB", [IntPtr]::Zero,
    [SuApi]::DIGCF_PRESENT -bor [SuApi]::DIGCF_ALLCLASSES)
if ($set -eq [IntPtr]::new(-1)) { Write-Host "[!] GetClassDevs 失败" -ForegroundColor Red; exit 1 }
Write-Host "[+] DeviceInfoSet = $set"

$dev = New-Object SuApi+SP_DEVINFO_DATA
$target = $false
for ($i = 0; $i -lt 500; $i++) {
    $dev.cbSize = [Runtime.InteropServices.Marshal]::SizeOf([type][SuApi+SP_DEVINFO_DATA])
    if (-not [SuApi]::SetupDiEnumDeviceInfo($set, $i, [ref]$dev)) { break }
    $sb = New-Object System.Text.StringBuilder 512
    $req = 0
    if ([SuApi]::SetupDiGetDeviceInstanceId($set, [ref]$dev, $sb, 512, [ref]$req)) {
        if ($sb.ToString() -like "$HardwareId*") {
            Write-Host "[+] 目标设备: $($sb.ToString())" -ForegroundColor Green
            $target = $true
            break
        }
    }
}
if (-not $target) { Write-Host "[!] 未找到设备" -ForegroundColor Red; exit 1 }

$dev.cbSize = [Runtime.InteropServices.Marshal]::SizeOf([type][SuApi+SP_DEVINFO_DATA])
[void][SuApi]::SetupDiSetSelectedDevice($set, [ref]$dev)

# ---- 关键步骤：限定 DriverPath 到 winusb.inf ----
$ip = New-Object SuApi+SP_DEVINSTALL_PARAMS
$ip.cbSize = [Runtime.InteropServices.Marshal]::SizeOf([type][SuApi+SP_DEVINSTALL_PARAMS])
$dev.cbSize = [Runtime.InteropServices.Marshal]::SizeOf([type][SuApi+SP_DEVINFO_DATA])
if ([SuApi]::SetupDiGetDeviceInstallParams($set, [ref]$dev, [ref]$ip)) {
    Write-Host "[*] 读到现有 InstallParams, DriverPath='$($ip.DriverPath)'"
} else {
    Write-Host "[!] GetDeviceInstallParams 失败: $([SuApi]::LastErr)，用默认值" -ForegroundColor Yellow
}
$ip.DriverPath = $InfPath
$ip.cbSize = [Runtime.InteropServices.Marshal]::SizeOf([type][SuApi+SP_DEVINSTALL_PARAMS])
$dev.cbSize = [Runtime.InteropServices.Marshal]::SizeOf([type][SuApi+SP_DEVINFO_DATA])
if (-not [SuApi]::SetupDiSetDeviceInstallParams($set, [ref]$dev, [ref]$ip)) {
    Write-Host "[!] SetDeviceInstallParams 失败: $([SuApi]::LastErr)" -ForegroundColor Red
    exit 2
}
Write-Host "[+] DriverPath 已限定为 winusb.inf" -ForegroundColor Green

# ---- 构建并枚举 ----
$ok = $false
foreach ($dt in @([SuApi]::SPDIT_COMPATDRIVER, [SuApi]::SPDIT_CLASSDRIVER)) {
    $dev.cbSize = [Runtime.InteropServices.Marshal]::SizeOf([type][SuApi+SP_DEVINFO_DATA])
    if (-not [SuApi]::SetupDiBuildDriverInfoList($set, [ref]$dev, $dt)) {
        Write-Host "[*] BuildDriverInfoList(type=$dt) 失败: $([SuApi]::LastErr)" -ForegroundColor DarkGray
        continue
    }
    Write-Host "[*] BuildDriverInfoList(type=$dt) 成功"
    $n = 0
    while ($true) {
        $drv = New-Object SuApi+SP_DRVINFO_DATA
        $drv.cbSize = [Runtime.InteropServices.Marshal]::SizeOf([type][SuApi+SP_DRVINFO_DATA])
        if (-not [SuApi]::SetupDiEnumDriverInfo($set, [ref]$dev, $dt, $n, [ref]$drv)) { break }
        Write-Host ("    [{0}] {1} / {2}" -f $n, $drv.Description, $drv.ProviderName)

        [void][SuApi]::SetupDiSetSelectedDriver($set, [ref]$dev, [ref]$drv)
        $rb = $false
        $dev.cbSize = [Runtime.InteropServices.Marshal]::SizeOf([type][SuApi+SP_DEVINFO_DATA])
        $drv.cbSize = [Runtime.InteropServices.Marshal]::SizeOf([type][SuApi+SP_DRVINFO_DATA])
        $r = [SuApi]::DiInstallDevice([IntPtr]::Zero, $set, [ref]$dev, [ref]$drv,
            ([SuApi]::INSTALLFLAG_FORCE -bor [SuApi]::INSTALLFLAG_NONINTERACTIVE), [ref]$rb)
        if ($r) {
            Write-Host "[+] DiInstallDevice 成功 (NeedReboot=$rb)" -ForegroundColor Green
            $ok = $true
            break
        } else {
            Write-Host "    DiInstallDevice 失败: $([SuApi]::LastErr)" -ForegroundColor Yellow
        }
        $n++
        if ($n -gt 20) { break }
    }
    if ($ok) { break }
}
[void][SuApi]::SetupDiDestroyDeviceInfoList($set)

if (-not $ok) { Write-Host "[!] 安装未成功" -ForegroundColor Red; exit 3 }

Write-Host "[*] 重启设备节点 ..."
pnputil /restart-device "$HardwareId\6&15E088B1&0&2" 2>&1 | Out-String | Write-Host
Start-Sleep -Seconds 3

# 验证 Service 是否绑定
$key = "HKLM:\SYSTEM\CurrentControlSet\Enum\$HardwareId\6&15E088B1&0&2"
if (Test-Path $key) {
    $svc = (Get-ItemProperty -Path $key -Name Service -ErrorAction SilentlyContinue).Service
    Write-Host "[*] Device Service = '$svc'" -ForegroundColor Cyan
}
