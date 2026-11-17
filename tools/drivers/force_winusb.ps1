# force_winusb.ps1 — 用 SetupAPI 把微软签名的 inbox winusb.inf 强制绑定到 EDL 设备
#
# 原理：
#   pnputil 会校验第三方 INF 的数字签名，自定义 INF 因此装不上。
#   但 C:\Windows\INF\winusb.inf 是微软自带且已签名的。
#   通过 SetupAPI 的 DiInstallDevice + INSTALLFLAG_FORCE，
#   可以绕开"硬件 ID 必须匹配"的检查，把 inbox 的 WinUSB 驱动绑到目标设备。
#
# 需要管理员权限。

param(
    [string]$HardwareId = "USB\VID_05C6&PID_9008",
    [string]$InfPath = "$env:WINDIR\INF\winusb.inf"
)

$ErrorActionPreference = "Stop"

# ---------- P/Invoke 声明 ----------
$cs = @'
using System;
using System.Runtime.InteropServices;

public static class SetupApi
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
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string Description;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string MfgName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string ProviderName;
        public long DriverDate;
        public long DriverVersion;
    }

    public const int DIGCF_PRESENT = 0x2;
    public const int DIGCF_ALLCLASSES = 0x4;
    public const int SPDIT_CLASSDRIVER = 0x1;
    public const int SPDIT_COMPATDRIVER = 0x2;
    public const int INSTALLFLAG_FORCE = 0x1;
    public const int INSTALLFLAG_NONINTERACTIVE = 0x4;
    public const int DIF_REGISTERDEVICE = 0x19;

    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr SetupDiGetClassDevs(IntPtr ClassGuid, string Enumerator,
        IntPtr hwndParent, int Flags);

    [DllImport("setupapi.dll", SetLastError = true)]
    public static extern bool SetupDiEnumDeviceInfo(IntPtr DeviceInfoSet, int MemberIndex,
        ref SP_DEVINFO_DATA DeviceInfoData);

    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool SetupDiGetDeviceInstanceId(IntPtr DeviceInfoSet,
        ref SP_DEVINFO_DATA DeviceInfoData, System.Text.StringBuilder DeviceInstanceId,
        int DeviceInstanceIdSize, out int RequiredSize);

    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool SetupDiBuildDriverInfoList(IntPtr DeviceInfoSet,
        ref SP_DEVINFO_DATA DeviceInfoData, int DriverType);

    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool SetupDiEnumDriverInfo(IntPtr DeviceInfoSet,
        ref SP_DEVINFO_DATA DeviceInfoData, int DriverType, int MemberIndex,
        ref SP_DRVINFO_DATA DriverInfoData);

    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool SetupDiSetSelectedDriver(IntPtr DeviceInfoSet,
        ref SP_DEVINFO_DATA DeviceInfoData, ref SP_DRVINFO_DATA DriverInfoData);

    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool SetupDiSetSelectedDevice(IntPtr DeviceInfoSet,
        ref SP_DEVINFO_DATA DeviceInfoData);

    [DllImport("newdev.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool DiInstallDevice(IntPtr hwndParent, IntPtr DeviceInfoSet,
        ref SP_DEVINFO_DATA DeviceInfoData, ref SP_DRVINFO_DATA DriverInfoData,
        int Flags, out bool NeedReboot);

    public static int LastErr { get { return Marshal.GetLastWin32Error(); } }
}
'@

Add-Type -TypeDefinition $cs -Language CSharp

Write-Host "[*] 目标硬件 ID: $HardwareId"
Write-Host "[*] 使用 INF   : $InfPath"

if (-not (Test-Path $InfPath)) {
    Write-Host "[!] INF 不存在" -ForegroundColor Red
    exit 1
}

# ---------- 找到目标设备 ----------
$hDev = [SetupApi]::SetupDiGetClassDevs([IntPtr]::Zero, "USB", [IntPtr]::Zero,
    [SetupApi]::DIGCF_PRESENT -bor [SetupApi]::DIGCF_ALLCLASSES)
if ($hDev -eq [IntPtr]::new(-1)) {
    Write-Host "[!] SetupDiGetClassDevs 失败" -ForegroundColor Red
    exit 1
}

$devData = New-Object SetupApi+SP_DEVINFO_DATA
$devData.cbSize = [Runtime.InteropServices.Marshal]::SizeOf($devData)

$found = $false
$i = 0
while ($true) {
    $devData.cbSize = [Runtime.InteropServices.Marshal]::SizeOf($devData)
    if (-not [SetupApi]::SetupDiEnumDeviceInfo($hDev, $i, [ref]$devData)) { break }
    $sb = New-Object System.Text.StringBuilder 512
    $req = 0
    if ([SetupApi]::SetupDiGetDeviceInstanceId($hDev, [ref]$devData, $sb, 512, [ref]$req)) {
        $id = $sb.ToString()
        if ($id -like "$HardwareId*") {
            Write-Host "[+] 找到设备: $id" -ForegroundColor Green
            $found = $true
            break
        }
    }
    $i++
}

if (-not $found) {
    Write-Host "[!] 未找到匹配设备" -ForegroundColor Red
    exit 1
}

# ---------- 用 winusb.inf 构建驱动列表并强制安装 ----------
$devData.cbSize = [Runtime.InteropServices.Marshal]::SizeOf($devData)
if (-not [SetupApi]::SetupDiSetSelectedDevice($hDev, [ref]$devData)) {
    Write-Host "[!] SetupDiSetSelectedDevice 失败: $([SetupApi]::LastErr)" -ForegroundColor Yellow
}

# 尝试 COMPATDRIVER（允许不严格匹配硬件 ID），遍历所有驱动条目找 WinUsb
$ok = $false
foreach ($dt in @([SetupApi]::SPDIT_COMPATDRIVER, [SetupApi]::SPDIT_CLASSDRIVER)) {
    [void][SetupApi]::SetupDiSetSelectedDevice($hDev, [ref]$devData)
    Write-Host "[*] 尝试 DriverType=$dt 构建驱动列表 ..."
    $devData.cbSize = [Runtime.InteropServices.Marshal]::SizeOf($devData)
    if (-not [SetupApi]::SetupDiBuildDriverInfoList($hDev, [ref]$devData, $dt)) {
        Write-Host "    SetupDiBuildDriverInfoList 失败: $([SetupApi]::LastErr)" -ForegroundColor Yellow
        continue
    }

    # 枚举所有条目，优先选 Description 含 WinUsb 的
    $n = 0
    $candidates = @()
    while ($true) {
        $drv = New-Object SetupApi+SP_DRVINFO_DATA
        $drv.cbSize = [Runtime.InteropServices.Marshal]::SizeOf($drv)
        if (-not [SetupApi]::SetupDiEnumDriverInfo($hDev, [ref]$devData, $dt, $n, [ref]$drv)) { break }
        $candidates += ,@{ Idx = $n; Desc = $drv.Description; Prov = $drv.ProviderName }
        Write-Host ("    [{0}] {1}  /  {2}" -f $n, $drv.Description, $drv.ProviderName)
        $n++
        if ($n -gt 40) { break }
    }
    if ($n -eq 0) {
        Write-Host "    SetupDiEnumDriverInfo 无结果: $([SetupApi]::LastErr)" -ForegroundColor Yellow
        continue
    }

    # 优先 WinUsb Device，其次包含 "USB" 的描述，最后退回第一个
    $pick = ($candidates | Where-Object { $_.Desc -match 'WinUsb' } | Select-Object -First 1)
    if (-not $pick) { $pick = ($candidates | Where-Object { $_.Desc -match 'USB|WinUSB' } | Select-Object -First 1) }
    if (-not $pick) { $pick = $candidates[0] }
    Write-Host ("[*] 选中 [{0}] {1}" -f $pick.Idx, $pick.Desc) -ForegroundColor Cyan

    $drv = New-Object SetupApi+SP_DRVINFO_DATA
    $drv.cbSize = [Runtime.InteropServices.Marshal]::SizeOf($drv)
    [void][SetupApi]::SetupDiEnumDriverInfo($hDev, [ref]$devData, $dt, $pick.Idx, [ref]$drv)
    [void][SetupApi]::SetupDiSetSelectedDriver($hDev, [ref]$devData, [ref]$drv)

    $needReboot = $false
    $devData.cbSize = [Runtime.InteropServices.Marshal]::SizeOf($devData)
    $drv.cbSize = [Runtime.InteropServices.Marshal]::SizeOf($drv)
    $r = [SetupApi]::DiInstallDevice([IntPtr]::Zero, $hDev, [ref]$devData, [ref]$drv,
        ([SetupApi]::INSTALLFLAG_FORCE -bor [SetupApi]::INSTALLFLAG_NONINTERACTIVE),
        [ref]$needReboot)
    if ($r) {
        Write-Host "[+] DiInstallDevice 成功 (NeedReboot=$needReboot)" -ForegroundColor Green
        $ok = $true
        break
    } else {
        Write-Host "    DiInstallDevice 失败: $([SetupApi]::LastErr)" -ForegroundColor Yellow
    }
}

if (-not $ok) {
    Write-Host "[!] 强制安装未成功" -ForegroundColor Red
    exit 2
}

Write-Host "[*] 触发设备重新扫描 ..."
pnputil /scan-devices | Out-Null
Start-Sleep -Seconds 3

Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue |
    Where-Object { $_.InstanceId -like "$HardwareId*" } |
    Select-Object Status, Class, FriendlyName | Format-List | Out-String | Write-Host
