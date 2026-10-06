<#
.SYNOPSIS
  监控 explorer.exe 重启，并在每次重启后自动执行（守卫版）去水印命令。

.DESCRIPTION
  ★ 本文件是「布局无关」的：只依赖「脚本所在目录的上一级 = 安装根」这个约定，
    因此同一份文件可以被 Windows 服务、计划任务、登录启动项等任意载体拉起，
    行为完全一致，不需要任何改动。

  默认按下面这个相对布局工作（<base> = 脚本所在目录的上一级）：
      <base>/<脚本所在目录>/
      <base>/<脚本所在目录>/config.json    实例配置（每个部署一份）
      <base>/log/service.log
  这些都可以用参数覆盖（见 -TargetExe / -LogDir / -ConfigFile）。

  与原版 monitor.ps1 的关键差别：
    - 执行目标时用 Start-Process -Wait -PassThru 拿到**真实退出码**并写日志，
      治掉"Start-Process 不看退出码、失败也记 Executing"造成的静默假成功；
    - 记录本次执行的耗时与退出码，语义：
        0 = 成功（已注入）；1 = 拿不到可信 RVA 而跳过；2 = 出错
        详见 run-watermark-guarded.ps1 的 .NOTES。

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File bin\monitor.ps1

.EXAMPLE
  # 只跑一轮检查后退出（供计划任务的一次性触发使用）
  powershell -NoProfile -ExecutionPolicy Bypass -File scripts\monitor.ps1 -Once

.EXAMPLE
  # 显式指定（脱离默认布局时）
  powershell -NoProfile -ExecutionPolicy Bypass -File scripts\monitor.ps1 -LogDir D:\x\log -TargetExe "D:\x\clear-watermark.cmd"
#>
[CmdletBinding()]
param(
    [string] $TargetProcess = "explorer",
    # 要执行的目标；默认取自 config.json 的 targetExe
    [string] $TargetExe  = "",
    # 实例配置；默认先找脚本同目录 config.json，再找 <base>\config.json
    [string] $ConfigFile = "",
    # 日志目录；默认 <base>\log
    [string] $LogDir     = "",
    # 0 = 用配置里的值；仍为 0 则 3 秒
    [int]    $CheckInterval = 0,
    # 0 = 用配置里的值；仍为 0 则 2000 行
    [int]    $LogMaxLines   = 0,
    # 只跑一轮检查后退出（不常驻）
    [switch] $Once
)

$ErrorActionPreference = 'Continue'

try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }
try { $OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }

# ---- 启动后自动隐藏控制台窗口 --------------------------------------------
# 由计划任务 / 登录启动项拉起时本来就没有窗口；但若从可视化控制台启动
# （双击某个 .cmd、或安装脚本用 WMI 拉起），会留下一个窗口占着桌面。
# 这里在启动后立刻把本进程的控制台窗口隐藏掉 —— 用户看不到、也不会残留。
try {
    if (-not ('Uwd2Win.ConsoleHost' -as [type])) {
        Add-Type -Namespace Uwd2Win -Name ConsoleHost -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("kernel32.dll")]
public static extern System.IntPtr GetConsoleWindow();
[System.Runtime.InteropServices.DllImport("user32.dll")]
public static extern bool ShowWindow(System.IntPtr hWnd, int nCmdShow);
'@ -ErrorAction Stop
    }
    $hWnd = [Uwd2Win.ConsoleHost]::GetConsoleWindow()
    if ($hWnd -ne [System.IntPtr]::Zero) {
        [void][Uwd2Win.ConsoleHost]::ShowWindow($hWnd, 0)   # 0 = SW_HIDE
    }
} catch { }

$baseDir = Split-Path $PSScriptRoot -Parent
# 载体名从安装目录名派生，避免在日志里写死某个产品名：
#   安装根目录为 <name> 时，日志里输出 "<name> monitor started"
$carrierName = Split-Path $baseDir -Leaf
$script:iterCount = 0

# ---------------------------------------------------------------- 实例配置
$cfg = $null
if (-not $ConfigFile) {
    foreach ($c in @((Join-Path $PSScriptRoot 'config.json'), (Join-Path $baseDir 'config.json'))) {
        if (Test-Path $c) { $ConfigFile = $c; break }
    }
}

if (-not $LogDir) { $LogDir = Join-Path $baseDir 'log' }
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

$logFile    = Join-Path $LogDir "service.log"
$stdoutFile = Join-Path $LogDir "stdout.log"
$stderrFile = Join-Path $LogDir "stderr.log"

if ($ConfigFile -and (Test-Path $ConfigFile)) {
    try { $cfg = Get-Content $ConfigFile -Raw -Encoding UTF8 | ConvertFrom-Json } catch { $cfg = $null }
}

if (-not $TargetExe) {
    if ($cfg -and $cfg.targetExe) {
        $t = [string]$cfg.targetExe
        # 相对路径按"脚本所在目录"解析（与项目原版行为一致）
        if (-not [System.IO.Path]::IsPathRooted($t)) { $t = Join-Path $PSScriptRoot $t }
        $TargetExe = [System.IO.Path]::GetFullPath($t)
    } else {
        $TargetExe = Join-Path $PSScriptRoot 'clear-watermark.cmd'
    }
}

if ($CheckInterval -le 0) {
    if ($cfg -and $cfg.checkInterval) { $CheckInterval = [int]$cfg.checkInterval }
    if ($CheckInterval -le 0) { $CheckInterval = 3 }
}
if ($LogMaxLines -le 0) {
    if ($cfg -and $cfg.logMaxLines) { $LogMaxLines = [int]$cfg.logMaxLines }
    if ($LogMaxLines -le 0) { $LogMaxLines = 2000 }
}

function Write-Log {
    param($msg)
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$ts] $msg"
    Add-Content -Path $logFile -Value $entry -Encoding UTF8
    Write-Host $entry
}

function Trim-Log {
    if (Test-Path $logFile) {
        $lines = Get-Content $logFile -ErrorAction SilentlyContinue
        if ($lines -and $lines.Count -gt $LogMaxLines) {
            $lines | Select-Object -Last $LogMaxLines | Set-Content $logFile -Encoding UTF8
        }
    }
}

function Invoke-Target {
    param([string] $Path)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $proc = Start-Process -FilePath $Path -WindowStyle Hidden -Wait -PassThru
        $code = $proc.ExitCode
        $sw.Stop()
        $secs = [math]::Round($sw.Elapsed.TotalSeconds, 1)
        if ($code -eq 0) {
            Write-Log "    -> exit=0 成功（已注入）  用时 ${secs}s"
        } elseif ($code -eq 1) {
            Write-Log "    -> exit=1 跳过：拿不到可信 RVA（符号未发布 / 迁移不可用）  用时 ${secs}s"
        } else {
            Write-Log "    -> exit=$code 失败（详见 log\service.log 与 log\watermark-exe.log）  用时 ${secs}s"
        }
    } catch {
        $sw.Stop()
        Write-Log "    -> 启动失败：$($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------- 启动日志
Write-Log "=========================================="
Write-Log "$carrierName monitor started$(if ($Once) { ' (Once)' })"
Write-Log "Base dir       : $baseDir"
Write-Log "Config         : $(if ($ConfigFile) { $ConfigFile } else { '(none)' })"
Write-Log "Target process : $targetProcess"
Write-Log "Target exe     : $TargetExe"
Write-Log "Check interval : ${CheckInterval}s"
Write-Log "Log directory  : $LogDir"
Write-Log "=========================================="

if (-not (Test-Path $TargetExe)) {
    Write-Log "ERROR: 目标不存在 -> $TargetExe"
}

$lastStartTime = $null
$firstRun = $true

# ---------------------------------------------------------------- 主循环
while ($true) {
    try {
        $procs = Get-Process -Name $TargetProcess -ErrorAction SilentlyContinue
        if ($procs) {
            $proc = $procs | Sort-Object StartTime -Descending | Select-Object -First 1
            $cur = $proc.StartTime
        } else {
            $proc = $null
            $cur = $null
        }

        if ($proc) {
            if ($null -eq $lastStartTime) {
                $lastStartTime = $cur
                Write-Log "Detected $targetProcess running since $cur"

                if ($firstRun) {
                    Write-Log "First run - executing $TargetExe"
                    Invoke-Target -Path $TargetExe
                    $firstRun = $false
                }
            } elseif ($cur -gt $lastStartTime) {
                Write-Log "Detected $targetProcess RESTART"
                Write-Log "Executing $TargetExe"
                Invoke-Target -Path $TargetExe
                $lastStartTime = $cur
            }
        } else {
            if ($null -ne $lastStartTime) {
                Write-Log "$targetProcess stopped - waiting for restart"
                $lastStartTime = $null
            }
        }
    } catch {
        $errMsg = "Error: $($_.Exception.Message)"
        Write-Log $errMsg
    }

    if ($Once) { break }

    Start-Sleep -Seconds $CheckInterval

    if (($script:iterCount = ($script:iterCount + 1) % 100) -eq 0) { Trim-Log }
}
