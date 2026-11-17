# crashlog.ps1 — PEGM10 内核崩溃日志抓取（实测可用路径）
#
# 背景（本机实测结论）：
#   /proc/kmsg          -> Permission denied
#   /dev/kmsg           -> Permission denied (root:system 620)
#   dmesg               -> klogctl denied (dmesg_restrict)
#   /sys/fs/pstore      -> SELinux 拒绝（DAC 上 shell 在 log 组，是策略挡的）
#   /cache/recovery/*   -> SELinux 拒绝（cache_file）
#   logcat -b kernel    -> 缓冲区存在但恒为 0 字节（logd 读不到 /dev/kmsg）
#   /data/persist_log   -> Permission denied
#
#   唯一能从主机侧拿到内核日志的路径：
#        adb bugreport  ->  压缩包里 FS/cache/recovery/last_kmsg*
#   （dumpstate 在自己的 SELinux 域里，权限足够）
#
# 工作流：
#   1. 触发可疑操作
#   2. 手机会 panic 并自动重启
#   3. 开机后立刻跑本脚本
#
# 用法：
#   pwsh -File crashlog.ps1
#   pwsh -File crashlog.ps1 -KeepReport        # 保留完整 bugreport.zip
#   pwsh -File crashlog.ps1 -Reuse <zip路径>   # 复用已有 bugreport，不重新抓

param(
    [switch]$KeepReport,
    [string]$Reuse,
    [string]$OutDir = "$PSScriptRoot\crashlogs"
)

$ErrorActionPreference = "Continue"
Add-Type -AssemblyName System.IO.Compression.FileSystem

if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"

function Wait-Device {
    Write-Host "[*] 等待设备上线..." -ForegroundColor Cyan
    for ($i = 0; $i -lt 150; $i++) {
        $d = (adb devices 2>&1) | Select-Object -Skip 1 | Where-Object { $_ -match '\S' }
        if ($d) { Write-Host "[+] 在线: $(($d -split '\s+')[0])" -ForegroundColor Green; return $true }
        Start-Sleep -Seconds 2
    }
    Write-Host "[!] 超时：设备没上线" -ForegroundColor Red
    return $false
}

# ---------- 1. 取 bugreport ----------
$zipPath = $Reuse
if (-not $Reuse) {
    if (-not (Wait-Device)) { exit 1 }
    Write-Host "[*] 等待 15 秒，让 ramoops -> pstore -> dropbox 的落库完成..."
    Start-Sleep -Seconds 15

    $zipPath = Join-Path $env:TEMP "pegm10-bugreport-$stamp.zip"
    Write-Host "[*] 抓 bugreport（约 1-2 分钟）..." -ForegroundColor Cyan
    & adb bugreport $zipPath 2>&1 | Select-Object -Last 2 | Out-Null
    if (-not (Test-Path $zipPath)) {
        Write-Host "[!] bugreport 失败" -ForegroundColor Red
        exit 1
    }
    Write-Host "[+] bugreport: $zipPath ($([math]::Round((Get-Item $zipPath).Length/1MB,2)) MB)" -ForegroundColor Green
}

# ---------- 2. 抽取 last_kmsg* ----------
$kmsgDir = Join-Path $OutDir "$stamp"
New-Item -ItemType Directory -Path $kmsgDir -Force | Out-Null

$z = [IO.Compression.ZipFile]::OpenRead($zipPath)
$got = 0
foreach ($e in $z.Entries) {
    if ($e.FullName -match '^FS/cache/recovery/(last_kmsg(\.[0-9]+)?|last_log|last_uboot_log)$') {
        $name = Split-Path $e.FullName -Leaf
        $dst = Join-Path $kmsgDir $name
        [IO.Compression.ZipFileExtensions]::ExtractToFile($e, $dst, $true)
        $got++
        Write-Host "    extracted $name ($([math]::Round($e.Length/1KB,0)) KB)"
    }
}
$z.Dispose()
Write-Host "[+] 抽出 $got 个内核日志文件 -> $kmsgDir" -ForegroundColor Green

# ---------- 3. 扫关键行 ----------
$patterns = 'Unable to handle|BUG:|Oops|Kernel panic|Call trace|PC is at|LR is at|' +
            'Internal error|general protection|slab-out-of-bounds|KASAN|' +
            'watchdog|kgsl|adreno|msm_kgsl|Unable to k|WARNING:|backtrace'
Write-Host "`n[*] 崩溃关键行：" -ForegroundColor Cyan
$hits = 0
Get-ChildItem $kmsgDir -Filter 'last_kmsg*' | Sort-Object LastWriteTime -Descending | ForEach-Object {
    $f = $_.FullName
    $m = Select-String -Path $f -Pattern $patterns
    if ($m) {
        Write-Host "`n--- $($_.Name) ---" -ForegroundColor Yellow
        $m | Select-Object -First 60 | ForEach-Object { $_.Line; $hits++ }
    }
}
if ($hits -eq 0) { Write-Host "    （没匹配到，可能是正常启动日志）" -ForegroundColor DarkGray }

# ---------- 4. dropbox 兜底 ----------
$dp = Join-Path $OutDir "$stamp-dropbox-LAST_KMSG.txt"
adb shell "dumpsys dropbox --print SYSTEM_LAST_KMSG" 2>&1 | Out-File $dp -Encoding utf8
if ((Get-Content $dp -Raw) -match 'No entries found') {
    Write-Host "[i] dropbox SYSTEM_LAST_KMSG: 无条目" -ForegroundColor DarkGray
    Remove-Item $dp -Force
} else {
    Write-Host "[+] dropbox SYSTEM_LAST_KMSG -> $dp" -ForegroundColor Green
}

# ---------- 5. 设备状态快照 ----------
$info = Join-Path $OutDir "$stamp-info.txt"
@(
    "=== uname ==="; (adb shell "uname -a" 2>&1)
    "=== boot reason ==="; (adb shell "getprop ro.boot.bootreason; getprop sys.boot.reason; getprop ro.boot.bootmode" 2>&1)
    "=== uptime ==="; (adb shell "cat /proc/uptime" 2>&1)
    "=== battery ==="; (adb shell "dumpsys battery | head -8" 2>&1)
) | Out-File $info -Encoding utf8

# ---------- 6. 清理 ----------
if (-not $KeepReport -and -not $Reuse) {
    Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
    Write-Host "[i] 已删除临时 bugreport（-KeepReport 可保留）" -ForegroundColor DarkGray
}

Write-Host "`n[+] 全部完成，产物在: $OutDir" -ForegroundColor Cyan
Write-Host "    崩溃时优先看 $stamp\last_kmsg 里的 Call trace 段" -ForegroundColor Cyan
