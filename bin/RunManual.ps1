<#
.SYNOPSIS
  手动执行一次去水印（走守卫链路，而不是直连 exe）。

.DESCRIPTION
  ★ 与 prewarm-rva.py / run-watermark-guarded.ps1 / monitor.ps1 / status.ps1 一样，
    本文件是「布局无关」的：同一个文件放进任意目录名的部署里都能直接用，
    可以直接命令行调用，也可以由任意双击壳（.bat/.cmd）转发。

  执行的目标取自 config.json 的 targetExe（默认就是 clear-watermark.cmd，即守卫入口），
  所以手动跑和后台自动跑**走的是同一条链路**：体检缓存 → 必要时预热/迁移 → 调原版 exe 注入。
  config / 日志目录 / 目标都能用参数覆盖，默认按 <base>（= 脚本所在目录的上一级）推断。

  退出码即目标程序的退出码：0 = 成功（已注入）；1 = 拿不到可信 RVA 而跳过；2 = 出错。

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File bin\RunManual.ps1

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File scripts\RunManual.ps1 -TargetExe D:\x\ClearWinWatermark.exe
#>
[CmdletBinding()]
param(
    # 覆盖 config.json 里的 targetExe
    [string] $TargetExe = "",
    # 实例配置；默认先找脚本同目录 config.json，再找 <base>\config.json
    [string] $ConfigFile = "",
    # 日志目录；默认 <base>\log
    [string] $LogDir = ""
)

$ErrorActionPreference = 'Continue'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }

$baseDir = Split-Path $PSScriptRoot -Parent

if (-not $ConfigFile) {
    foreach ($c in @((Join-Path $PSScriptRoot 'config.json'), (Join-Path $baseDir 'config.json'))) {
        if (Test-Path $c) { $ConfigFile = $c; break }
    }
}
if (-not $LogDir) { $LogDir = Join-Path $baseDir 'log' }
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
$logPath = Join-Path $LogDir 'manual.log'

function Log {
    param($msg)
    $t = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "[$t] MANUAL $msg" | Add-Content $logPath -Encoding UTF8
    Write-Host "[$t] $msg"
}

Write-Host "================ 手动执行去水印 ================" -ForegroundColor Cyan
Write-Host "配置     : $(if ($ConfigFile) { $ConfigFile } else { '(未找到)' })"
Write-Host "日志目录 : $LogDir"

# 解析目标
if (-not $TargetExe) {
    $cfg = $null
    if ($ConfigFile -and (Test-Path $ConfigFile)) {
        try { $cfg = Get-Content $ConfigFile -Raw -Encoding UTF8 | ConvertFrom-Json } catch { }
    }
    if ($cfg -and $cfg.targetExe) {
        $t = [string]$cfg.targetExe
        if (-not [System.IO.Path]::IsPathRooted($t)) { $t = Join-Path $PSScriptRoot $t }
        $TargetExe = [System.IO.Path]::GetFullPath($t)
    } else {
        $TargetExe = Join-Path $PSScriptRoot 'clear-watermark.cmd'
    }
}
Write-Host "目标     : $TargetExe"
Write-Host ""

if (-not (Test-Path $TargetExe)) {
    Log "ERROR: 目标不存在 -> $TargetExe"
    Write-Host "目标不存在，已放弃。" -ForegroundColor Red
    exit 2
}

$sw = [System.Diagnostics.Stopwatch]::StartNew()
try {
    Log "Starting: $TargetExe"
    $proc = Start-Process -FilePath $TargetExe -WindowStyle Hidden -Wait -PassThru
    $code = $proc.ExitCode
    $sw.Stop()
    $secs = [math]::Round($sw.Elapsed.TotalSeconds, 1)

    if ($code -eq 0) {
        Log "OK (exit=0, ${secs}s) —— 已注入，水印应已消失"
        Write-Host "成功：注入完成（exit=0，用时 ${secs}s）" -ForegroundColor Green
    } elseif ($code -eq 1) {
        Log "SKIPPED (exit=1, ${secs}s) —— 拿不到可信 RVA，未执行注入"
        Write-Host "跳过：拿不到可信 RVA（本 build 符号未发布且相邻 build 迁移不可用）。" -ForegroundColor Yellow
        Write-Host "      详情见 $LogDir\rva-cache.log；可等微软发布符号后重试。" -ForegroundColor Yellow
    } else {
        Log "FAILED (exit=$code, ${secs}s) —— 见 $LogDir\service.log 与 watermark-exe.log"
        Write-Host "失败：退出码 $code（见 $LogDir\service.log 与 watermark-exe.log）" -ForegroundColor Red
    }
    exit $code
}
catch {
    $sw.Stop()
    Log "ERROR: $($_.Exception.Message)"
    Write-Host "执行出错：$($_.Exception.Message)" -ForegroundColor Red
    exit 2
}
