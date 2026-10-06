<#
.SYNOPSIS
  ClearWinWatermark.exe 的「守卫 + 预热」外层包装：不改动 exe 也能稳定运行。

.DESCRIPTION
  ClearWinWatermark.exe（UWD2, https://github.com/machineonamission/uwd2）的工作方式：
    1) 从本机 shell32.dll 读出 CodeView GUID，拼成符号索引 <GUID><Age>；
    2) 若 %APPDATA%\reticivis\UWD2\data\<索引>.rva 已有缓存 -> 直接用里面的 RVA（不联网）；
       否则去 msdl 下载 shell32.pdb，再在 PDB 里查 CDesktopWatermark::s_DesktopBuildPaint 的 RVA；
    3) 把该 RVA 处的第一个字节写成 0xC3 (RET)，注入 explorer.exe 内存，水印就不再绘制。

  两个坑（都在 exe 之外解决）：
    A. 当前 Windows 版本（Insider 预览版 / 刚更新的版本）符号还没发布时，第 2 步一定 404，
       exe 里的 unwrap() 直接 panic（就是那条 fetch_pdb.rs:8:47 报错）。
    B. 如果缓存里塞的是**别的 build** 算出来的 RVA（例如硬编码 GUID 的旧版本写进去的值），
       exe 会"看起来正常运行"，但实际 patch 到无关函数的中间 —— 会破坏栈平衡。
       缓存文件名用的是本机 GUID，内容却可能是别的 build 的 RVA，这个错位非常隐蔽。

  ★ 本脚本是「布局无关」的：只依赖下面这个相对布局（<base> = 脚本所在目录的上一级），
    因此同一份文件可以原样放进任意目录名的部署里，无需任何改动：
        <base>/<脚本所在目录>/
        <base>/tools/ClearWinWatermark.exe
        <base>/log/
    exe / 日志目录 / 配置文件都可用参数或环境变量覆盖，见下。

  ★ 本脚本同时中和一类「假失败」：ClearWinWatermark.exe 在**没有交互桌面**的上下文里
    （例如以 LocalSystem 运行的 Windows 服务，session 0）最后一步「通知桌面重绘」必然失败，
    返回 101 / HRESULT 0x80070578 —— 但它在那之前已经打印过 "Injected!"，
    内存其实改成功了。本脚本在 exe 非 0 退出时会再跑一次内存复核（verify-inject.py），
    已注入即判定成功，避免每次 explorer 重启都在日志里留一条吓人的「执行失败」。

  执行顺序（monitor.ps1 调用本脚本，而不是直接调用 exe）：
    0) 跑 prewarm-rva.py --verify，退出码：0 缓存就绪 / 4 缓存缺失 / 2 缓存校验未通过
       - 就绪 -> 直接执行 exe（完全离线）
       - 缺失或校验失败 -> 依次尝试三条来源，**只有硬校验通过才会写入缓存**：
         ⓪ 同机其它档案的缓存（离线播种；服务账号 LocalSystem 的关键兜底）
         ① 本 build 的 shell32.pdb（按本机 GUID+Age 索引，msdl）
         ② 相邻 build 迁移（本 build 符号未发布时的兜底，见下）
         · 三条都拿不到 -> 跳过不执行（无 panic 噪音），等 explorer 下次重启再试
         · 校验不通过 -> 跳过，**不写入**错误 RVA

       相邻 build 迁移是怎么做的：
         从 WinbIndex 的 Insider 索引里挑出「更早、SizeOfImage 与本机最接近」的 build
         （同一 build 下 shell32.dll 有 x64 / ARM64 / x86 三种架构，用 SizeOfImage 先挑出
         x64 那一份，避免白下 15MB 的 ARM64）→ 下载它的 shell32.dll + shell32.pdb
         → 从 PDB 里取 CDesktopWatermark::s_DesktopBuildPaint 的 RVA
         → 用该函数体的多个 24 字节锚点在**本机 shell32.dll** 里投票重新定位
         → 要求：票数集中唯一、落点是 .pdata 函数入口、函数大小与参考 build 完全一致。
       实测：参考 build 29671 → 本机 29680，29 票（次高 1）命中 0x081d28，size 0xa1f 全等。
       参考 DLL/PDB 会缓存在 %TEMP%\uwd2_prewarm\，之后重跑不再下载。

    1) 若 Python 不可用，退回 check-symbols.ps1 的"符号是否已发布"探测；
    2) 启动原版 ClearWinWatermark.exe（exe 一个字节都不改），记录 stdout/stderr 与退出码；
    3) exe 非 0 退出时复核 explorer 内存，区分「真失败」与「无桌面导致的假失败」。

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File bin\run-watermark-guarded.ps1

.EXAMPLE
  # 只体检缓存、不做任何执行
  powershell -NoProfile -ExecutionPolicy Bypass -File bin\run-watermark-guarded.ps1 -CheckOnly

.EXAMPLE
  # 显式指定 exe 与日志目录（脱离默认布局时用）
  powershell -NoProfile -ExecutionPolicy Bypass -File scripts\run-watermark-guarded.ps1 -Exe D:\x\ClearWinWatermark.exe -LogDir D:\x\log

.EXAMPLE
  # 跳过所有检查直接执行（例如已确认缓存就绪）
  powershell -NoProfile -ExecutionPolicy Bypass -File bin\run-watermark-guarded.ps1 -Force

.NOTES
  exe 定位优先级：-Exe 参数 > 环境变量 UWD2_EXE > config.json 的 exePath > 自动发现。
  退出码：0 = 已执行且注入成功（含「exe 非 0 但内存复核确认已注入」）；
         1 = 拿不到可信 RVA（本 build 符号未发布且相邻 build 迁移也不可用）而跳过；
         2 = 出错、缓存校验失败、或 exe 非 0 且内存复核未确认注入。
#>
[CmdletBinding()]
param(
    [string]   $Exe    = "",
    [string[]] $Arguments = @(),
    [string]   $Target = "$env:SystemRoot\System32\shell32.dll",
    [string]   $Server = "https://msdl.microsoft.com/download/symbols",
    [int]      $ExeTimeoutSec = 180,
    # 覆盖 <base>（= 脚本所在目录的上一级）的推断，一般不用传
    [string]   $BaseDir = "",
    # 日志目录（默认 <base>\log）
    [string]   $LogDir = "",
    # 实例配置（默认先找脚本同目录 config.json，再找 <base>\config.json）
    [string]   $ConfigFile = "",
    # 只体检（缓存校验 + 符号探测），不执行 exe
    [switch]   $CheckOnly,
    # 跳过所有检查，直接执行
    [switch]   $Force
)

$ErrorActionPreference = 'Stop'

# 让 PowerShell 用 UTF-8 解码子进程（python）的输出，避免中文写进日志变乱码
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }
try { $OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }

if (-not $BaseDir) { $BaseDir = Split-Path $PSScriptRoot -Parent }

# ---- 读实例配置（可选；每个部署各自一份，不属于核心逻辑）----
$cfg = $null
if (-not $ConfigFile) {
    foreach ($c in @((Join-Path $PSScriptRoot 'config.json'), (Join-Path $BaseDir 'config.json'))) {
        if (Test-Path $c) { $ConfigFile = $c; break }
    }
}
if ($ConfigFile -and (Test-Path $ConfigFile)) {
    try { $cfg = Get-Content $ConfigFile -Raw -Encoding UTF8 | ConvertFrom-Json } catch { $cfg = $null }
}

# ---- 定位 ClearWinWatermark.exe ----
if (-not $Exe -and $env:UWD2_EXE) { $Exe = $env:UWD2_EXE }
if (-not $Exe -and $cfg -and $cfg.exePath) {
    $p = [string]$cfg.exePath
    if (-not [System.IO.Path]::IsPathRooted($p)) { $p = Join-Path $PSScriptRoot $p }
    if (Test-Path $p) { $Exe = [System.IO.Path]::GetFullPath($p) }
}
if (-not $Exe) {
    # 按常见布局自动定位（不写死单一目录，方便把脚本单独搬走用）：
    #   ① <base>\tools\   —— 推荐的标准布局
    #   ② <base>\         —— exe 就在上一级
    #   ③ 脚本同目录 / 脚本同目录的 tools\
    foreach ($c in @(
            (Join-Path $BaseDir 'tools\ClearWinWatermark.exe'),
            (Join-Path $BaseDir 'ClearWinWatermark.exe'),
            (Join-Path $PSScriptRoot 'ClearWinWatermark.exe'),
            (Join-Path $PSScriptRoot 'tools\ClearWinWatermark.exe'))) {
        if (Test-Path $c) { $Exe = $c; break }
    }
    if (-not $Exe) { $Exe = Join-Path $BaseDir 'tools\ClearWinWatermark.exe' }   # 兜底：交给下面的存在性检查报错
}

# ---- 日志目录 ----
if (-not $LogDir) {
    if ($cfg -and $cfg.logDir) {
        $LogDir = [string]$cfg.logDir
        if (-not [System.IO.Path]::IsPathRooted($LogDir)) { $LogDir = Join-Path $BaseDir $LogDir }
    } else {
        $LogDir = Join-Path $BaseDir 'log'
    }
}
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
$logFile = Join-Path $LogDir 'service.log'
$exeLog  = Join-Path $LogDir 'watermark-exe.log'
$preLog  = Join-Path $LogDir 'rva-cache.log'

function Write-GuardLog {
    param([string] $Message)
    $entry = "[{0}] [guard] {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
    Add-Content -Path $logFile -Value $entry -Encoding UTF8
}

function Resolve-Python {
    # 通用发现顺序，不写死任何机器专属路径：
    #   ① PATH 上的 python.exe → ② py 启动器 → ③ 常见安装位置
    $cmd = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $py = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($py) {
        try {
            $p = & $py.Source -3 -c "import sys;print(sys.executable)" 2>$null
            if ($p -and (Test-Path $p)) { return $p }
        } catch { }
    }
    $cands = @()
    foreach ($la in @($env:LOCALAPPDATA, $env:ProgramFiles, ${env:ProgramFiles(x86)})) {
        if (-not $la) { continue }
        foreach ($v in @('Python313', 'Python312', 'Python311', 'Python310', 'Python39')) {
            $cands += (Join-Path $la "Programs\Python\$v\python.exe")
            $cands += (Join-Path $la "$v\python.exe")
        }
    }
    if ($env:SystemDrive) { $cands += (Join-Path $env:SystemDrive 'Python312\python.exe') }
    foreach ($c in $cands) { if ($c -and (Test-Path $c)) { return $c } }
    return $null
}

$python = Resolve-Python

if (-not (Test-Path $Exe)) {
    Write-GuardLog "ERROR: 目标EXE不存在 -> $Exe（可用 -Exe 指定、或设环境变量 UWD2_EXE）"
    exit 2
}

$ready = $false   # 缓存是否已就绪（校验通过）

# ---- 0. 外层预热：缓存校验 / 下载解析 / 校验后写缓存 ----
if (-not $Force) {
    $prewarm = Join-Path $PSScriptRoot 'prewarm-rva.py'

    if ((Test-Path $prewarm) -and $python) {
        $stamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        Add-Content -Path $preLog -Value ("===== [{0}] prewarm (python={1}) =====" -f $stamp, $python) -Encoding UTF8

        $verifyOut = & $python $prewarm --verify --shell32 $Target 2>&1 | Out-String
        $verifyCode = $LASTEXITCODE
        Add-Content -Path $preLog -Value $verifyOut.TrimEnd() -Encoding UTF8

        if ($verifyCode -eq 0) {
            $ready = $true
            Write-GuardLog "RVA 缓存已就绪且校验通过（可离线注入）-> 准备执行 $Exe"
        } else {
            if ($verifyCode -eq 4) {
                Write-GuardLog "RVA 缓存缺失（本机还没有这个索引的 .rva）-> 尝试预热"
            } elseif ($verifyCode -eq 2) {
                Write-GuardLog "RVA 缓存存在但校验未通过（内容与本机 shell32 不匹配）-> 尝试预热覆盖"
            } else {
                Write-GuardLog "缓存体检异常退出（verify exit=$verifyCode）-> 尝试预热"
            }

            $warmOut = & $python $prewarm --shell32 $Target 2>&1 | Out-String
            $warmCode = $LASTEXITCODE
            Add-Content -Path $preLog -Value $warmOut.TrimEnd() -Encoding UTF8

            if ($warmCode -eq 0) {
                $ready = $true
                Write-GuardLog "RVA 缓存预热成功且校验通过 -> 准备执行 $Exe"
            } elseif ($warmCode -eq 1) {
                Write-GuardLog "跳过：拿不到可信 RVA —— 本 build 的 shell32.pdb 尚未在微软符号服务器发布（404），且相邻 build 迁移也不可用。"
                Write-GuardLog "      此时 ClearWinWatermark.exe 会 panic，本次不执行（无副作用）。详情见 $LogDir\rva-cache.log"
                exit 1
            } else {
                Write-GuardLog "跳过：符号存在但与当前 shell32 不匹配（校验失败，已拒绝写入错误 RVA）。详情见 $LogDir\rva-cache.log"
                exit 2
            }
        }
    } else {
        # Python 不可用 -> 退回原逻辑：只看符号是否已发布
        $checker = Join-Path $PSScriptRoot 'check-symbols.ps1'
        if (Test-Path $checker) {
            & $checker -Target $Target -Server $Server -NoLog -Exe $Exe -LogDir $LogDir | Out-Null
            $code = $LASTEXITCODE
            if ($code -eq 1) {
                Write-GuardLog "跳过：shell32.pdb 尚未发布，本次不执行（无 Python，无法预热缓存）。详情见 $LogDir\symbol-check.log"
                exit 1
            }
            if ($code -ne 0) {
                Write-GuardLog "跳过：符号探测脚本异常退出（exit=$code），本次不执行。"
                exit 2
            }
            Write-GuardLog "符号已在微软符号服务器发布 -> 准备执行 $Exe（缓存将由 exe 自行生成）"
        } else {
            Write-GuardLog "警告：既无 prewarm-rva.py 也无 check-symbols.ps1，跳过检查直接执行"
        }
    }
} else {
    Write-GuardLog "（-Force）跳过缓存校验与符号检查 -> 准备执行 $Exe"
}

if ($CheckOnly) {
    if ($ready) { Write-GuardLog "（-CheckOnly）缓存就绪，未执行 exe"; exit 0 }
    Write-GuardLog "（-CheckOnly）缓存未就绪，未执行 exe"
    exit 1
}

# ---- 1. 启动 exe 并记录输出/退出码（避免"静默假成功"）----
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName               = $Exe
$psi.Arguments              = ($Arguments -join ' ')
$psi.UseShellExecute        = $false
$psi.CreateNoWindow         = $true
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError  = $true
$psi.WorkingDirectory       = (Split-Path $Exe -Parent)

$proc = New-Object System.Diagnostics.Process
$proc.StartInfo = $psi
$null = $proc.Start()
$stdout = $proc.StandardOutput.ReadToEnd()
$stderr = $proc.StandardError.ReadToEnd()
if (-not $proc.WaitForExit($ExeTimeoutSec * 1000)) {
    try { $proc.Kill() } catch { }
    Write-GuardLog "警告：$Exe 超过 ${ExeTimeoutSec}s 未退出，已强制结束"
}
$exitCode = $proc.ExitCode

$stamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
Add-Content -Path $exeLog -Value ("===== [{0}] {1} (exit={2}) =====" -f $stamp, $Exe, $exitCode) -Encoding UTF8
if ($stdout) { Add-Content -Path $exeLog -Value $stdout.TrimEnd() -Encoding UTF8 }
if ($stderr) { Add-Content -Path $exeLog -Value ("[stderr] " + $stderr.TrimEnd()) -Encoding UTF8 }

if ($exitCode -eq 0) {
    Write-GuardLog "执行完成：$Exe 退出码 0（输出见 $LogDir\watermark-exe.log）"
    exit 0
}

# ---- 2. exe 非 0 退出：先复核内存，区分「真失败」与「无交互桌面导致的假失败」----
# 已知假失败：服务以 LocalSystem / session 0 运行时，exe 最后一步"通知桌面重绘"必然
# 失败并打印 HRESULT(0x80070578) 无效的窗口句柄，退出码 101 —— 但它在 panic 之前
# 已经打印过 "Injected!"，写内存那步其实已完成。所以不能只看退出码。
$verifier = Join-Path $PSScriptRoot 'verify-inject.py'
if ((Test-Path $verifier) -and $python) {
    $vOut  = & $python $verifier 2>&1 | Out-String
    $vCode = $LASTEXITCODE
    Add-Content -Path $exeLog -Value ("----- 内存复核（exe exit={0}）-----" -f $exitCode) -Encoding UTF8
    Add-Content -Path $exeLog -Value $vOut.TrimEnd() -Encoding UTF8

    if ($vCode -eq 0) {
        Write-GuardLog "判定为成功：$Exe 退出码 $exitCode，但内存复核确认目标字节已是 0xC3（已注入）。"
        Write-GuardLog "      原因通常是运行环境没有交互桌面（服务/session 0）：只有最后一步「刷新桌面」失败，注入本身已完成。"
        exit 0
    }
    Write-GuardLog "执行失败：$Exe 退出码 $exitCode，且内存复核显示未注入（verify exit=$vCode）。"
    Write-GuardLog "      详情见 $LogDir\watermark-exe.log"
    exit 2
}

Write-GuardLog "执行失败：$Exe 退出码 $exitCode（无 verify-inject.py，无法复核内存；输出见 $LogDir\watermark-exe.log）"
exit 2
