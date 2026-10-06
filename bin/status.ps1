<#
.SYNOPSIS
  一体化状态体检：载体（服务/计划任务/登录启动项）+ RVA 缓存 + 注入状态 + 最近日志。
  布局无关：同一份文件放进任意目录名的部署里都能直接用。

.DESCRIPTION
  本脚本不假设自己属于哪个部署，而是**探测本机实际存在的载体**：
    [A]  Windows 服务：自动发现所有「命令行里调用了 monitor.ps1」的服务
         （nssm 托管、开机自启；各部署服务名不同，不写死）
    [B1] 任何「动作里调用了 monitor.ps1」的计划任务（当前用户，登录触发；注册需管理员）
    [B2] HKCU 登录启动项里任何「调用了 monitor.ps1」的值（B1 的免管理员替代载体）
  按「谁调用了 monitor.ps1」探测，不写死任何载体名；哪个存在就报告哪个，
  多个载体可共存，互不冲突、幂等。

  报告内容：
    1) 载体状态（服务 / 计划任务 / monitor.ps1 进程是否在跑）
    2) RVA 缓存体检：调用 prewarm-rva.py --verify
         退出码 0 = 就绪；4 = 缺失；2 = 内容与本机 shell32 不匹配；3 = 环境错误
    3) 注入状态：调用 verify-inject.py 直接读 explorer 内存里 shell32 + RVA 的首字节
         0xC3 = 已注入；其他 = 尚未注入
    4) 最近日志：service.log / watermark-exe.log / rva-cache.log 尾部

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File bin\status.ps1

.EXAMPLE
  # 不联网、不读内存，只看载体与缓存
  powershell -NoProfile -ExecutionPolicy Bypass -File scripts\status.ps1 -NoProbe

.NOTES
  退出码：0 = 一切正常（缓存就绪）；1 = 缓存不可用（缺失或校验失败）；
         2 = 脚本自身出错。
#>
[CmdletBinding()]
param(
    # 留空 = 自动发现所有「命令行里调用了 monitor.ps1」的 Windows 服务
    [string] $ServiceName = "",
    # 留空 = 自动探测「动作里调用了 monitor.ps1」的计划任务与登录启动项
    [string] $TaskName    = "",
    [string] $Target      = "$env:SystemRoot\System32\shell32.dll",
    [string] $BaseDir     = "",
    [string] $LogDir      = "",
    # 日志尾部显示行数
    [int]    $Tail        = 12,
    # 跳过内存探测（verify-inject.py）
    [switch] $NoProbe
)

$ErrorActionPreference = 'Continue'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }
try { $OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }

if (-not $BaseDir) { $BaseDir = Split-Path $PSScriptRoot -Parent }
if (-not $LogDir)  { $LogDir  = Join-Path $BaseDir 'log' }

function Section {
    param([string] $Title)
    Write-Host ""
    Write-Host ("-" * 74) -ForegroundColor DarkGray
    Write-Host " $Title" -ForegroundColor Cyan
    Write-Host ("-" * 74) -ForegroundColor DarkGray
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
$cacheOk = $false
$svcPid = $null

Write-Host "==================== UWD2 去水印 · 状态体检 ====================" -ForegroundColor Cyan
Write-Host ("时间     : {0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
Write-Host ("基准目录 : {0}" -f $BaseDir)
Write-Host ("shell32  : {0}" -f $Target)
Write-Host ("Python   : {0}" -f $(if ($python) { $python } else { '(未找到，缓存体检将跳过)' }))

# ---------------------------------------------------------------- 1. 载体
Section "1. 载体（谁是触发者）"

# [A] 服务：自动发现所有「ImagePath/命令行里调用了 monitor.ps1」的 Windows 服务，
#     不写死服务名（各部署的服务名不同）；显式传 -ServiceName 时额外兼容旧式检查。
$svcs = @()
try {
    $svcs = @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object {
        $_.PathName -and ($_.PathName -like '*monitor.ps1*')
    })
} catch { }
if ($ServiceName -and -not ($svcs | Where-Object { $_.Name -eq $ServiceName })) {
    $named = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
    if ($named) { $svcs += $named }
}
if ($svcs) {
    foreach ($s in $svcs) {
        $svcObj = Get-Service -Name $s.Name -ErrorAction SilentlyContinue
        $extra = "  StartName=$($s.StartName)  pid=$($s.ProcessId)"
        $mine = if ($s.PathName -like "*$BaseDir*") { "  <- 本套" } else { "" }
        Write-Host ("[A] 服务 {0,-32} : {1}{2}{3}" -f $s.Name, $(if ($svcObj) { $svcObj.Status } else { $s.State }), $extra, $mine) -ForegroundColor Green
        if ($s.StartName -eq 'LocalSystem') {
            Write-Host "    提示：LocalSystem/session 0 没有交互桌面，exe 最后一步「刷新桌面」必然失败" -ForegroundColor DarkGray
            Write-Host "          （退出码 101）—— 但注入已完成，守卫脚本会复核内存并判定成功。" -ForegroundColor DarkGray
        }
        # 后面父子进程判定用的 svcPid：优先取「本套」服务，否则取第一个
        if ($null -eq $svcPid -or $s.PathName -like "*$BaseDir*") { $svcPid = $s.ProcessId }
    }
} else {
    Write-Host "[A] 服务 : 未安装（没有任何命令行调用 monitor.ps1 的 Windows 服务）" -ForegroundColor DarkGray
}

# [B] 计划任务：按「动作里是否调用 monitor.ps1」探测，不写死任何任务名
$tasks = @()
try {
    $tasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
        $acts = @($_.Actions)
        $acts -and ($acts | Where-Object { ("$($_.Execute) $($_.Arguments)") -like '*monitor.ps1*' })
    })
} catch { }
if ($TaskName) { $tasks = @($tasks | Where-Object { $_.TaskName -eq $TaskName }) }
if ($tasks) {
    foreach ($t in $tasks) {
        $ti = Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction SilentlyContinue
        Write-Host ("[B1] 计划任务 {0,-27} : {1}" -f $t.TaskName, $t.State) -ForegroundColor Green
        if ($ti) {
            Write-Host ("     LastRunTime={0}  LastTaskResult={1}" -f $ti.LastRunTime, $ti.LastTaskResult)
        }
    }
} else {
    Write-Host "[B1] 计划任务 : 未安装（没有任何计划任务调用 monitor.ps1）" -ForegroundColor DarkGray
}

# [B] HKCU 登录启动项（install.ps1 在无管理员权限时的替代载体）
# 同样按「值里是否调用 monitor.ps1」探测，不写死任何项名。
$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$runHits = @()
if (Test-Path $runKey) {
    try {
        $props = Get-ItemProperty -Path $runKey -ErrorAction SilentlyContinue
        foreach ($p in $props.PSObject.Properties) {
            if ($p.Name -like 'PS*') { continue }
            if ("$($p.Value)" -like '*monitor.ps1*') {
                $runHits += [pscustomobject]@{ Name = $p.Name; Value = "$($p.Value)" }
            }
        }
    } catch { }
}
if ($TaskName) { $runHits = @($runHits | Where-Object { $_.Name -eq $TaskName }) }
if ($runHits) {
    foreach ($h in $runHits) {
        Write-Host ("[B2] 登录启动项 {0,-25} : 已注册" -f $h.Name) -ForegroundColor Green
        Write-Host ("     值：{0}" -f $h.Value)
    }
} else {
    Write-Host "[B2] 登录启动项 : 未注册（Run 键里没有任何调用 monitor.ps1 的项）" -ForegroundColor DarkGray
}

# monitor.ps1 进程（两路探测，缺一不可）
#
# 路 ①：命令行可读时，按「以 -File 显式加载 monitor.ps1」精确匹配。
#        不能只匹配 'monitor.ps1' 字样 —— 查询命令自身的命令行里恰好含这个字符串，
#        会把查询进程自己也算进来，出现假的多实例。
# 路 ②：**跨账户兜底**。非提权会话读不到 LocalSystem 等其它账户进程的 CommandLine
#        （Win32_Process 会返回空），此时路 ① 必然漏掉正在跑的服务常驻进程，
#        表现成「明明服务在跑却报没有 monitor 进程」。这里改用父子关系判定：
#        服务进程（nssm，pid=$svcPid）的 powershell 子进程就是该服务的 monitor。
$mons = @()
$monPids = @{}
try {
    foreach ($m in (Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue |
                    Where-Object { $_.CommandLine -and $_.CommandLine -like '*-File*monitor.ps1*' })) {
        $mons += $m; $monPids[[string]$m.ProcessId] = $true
    }
} catch { }
if ($svcPid) {
    try {
        foreach ($c in (Get-CimInstance Win32_Process -Filter "ParentProcessId=$svcPid" -ErrorAction SilentlyContinue |
                        Where-Object { $_.Name -like 'powershell*' })) {
            if (-not $monPids.ContainsKey([string]$c.ProcessId)) {
                $mons += $c; $monPids[[string]$c.ProcessId] = $true
            }
        }
    } catch { }
}
if ($mons) {
    foreach ($m in $mons) {
        if ($m.CommandLine) {
            $who = if ($m.CommandLine -like "*$BaseDir*") { "本套" } else { "其它目录" }
        } else {
            $who = "服务账户子进程（命令行跨账户不可读，按父子关系判定）"
        }
        Write-Host ("[活] monitor.ps1 pid={0}  ({1})" -f $m.ProcessId, $who) -ForegroundColor Green
    }
} else {
    Write-Host "[活] 没有探测到常驻 monitor 进程 —— explorer 重启后不会自动重新注入" -ForegroundColor Yellow
}

# ---------------------------------------------------------------- 2. RVA 缓存
Section "2. RVA 缓存（exe 的输入）"
$prewarm = Join-Path $PSScriptRoot 'prewarm-rva.py'
if ((Test-Path $prewarm) -and $python) {
    $out = & $python $prewarm --verify --shell32 $Target 2>&1 | Out-String
    $code = $LASTEXITCODE
    Write-Host $out.TrimEnd()
    switch ($code) {
        0 { Write-Host "→ 缓存就绪：exe 会命中缓存直接注入，完全不联网。" -ForegroundColor Green; $cacheOk = $true }
        4 { Write-Host "→ 缓存缺失：下次执行时守卫会先预热（离线播种 / 本build PDB / 相邻build迁移）。" -ForegroundColor Yellow }
        2 { Write-Host "→ 缓存内容与本机 shell32 不匹配！守卫会拒绝使用并重新预热（或加 --quarantine 隔离）。" -ForegroundColor Red }
        3 { Write-Host "→ 环境错误（读不到 shell32 或函数表）。" -ForegroundColor Red }
        default { Write-Host "→ 未知退出码 $code" -ForegroundColor Red }
    }
} else {
    Write-Host "(跳过：$prewarm 或 Python 不可用)"
}

# ---------------------------------------------------------------- 3. 注入状态
Section "3. 注入状态（直接读 explorer 内存）"
if ($NoProbe) {
    Write-Host "(已用 -NoProbe 跳过)"
} else {
    $verifier = Join-Path $PSScriptRoot 'verify-inject.py'
    if ((Test-Path $verifier) -and $python) {
        $out = & $python $verifier 2>&1 | Out-String
        $code = $LASTEXITCODE
        Write-Host $out.TrimEnd()
        switch ($code) {
            0 { Write-Host "→ 已注入（首字节 0xC3）。" -ForegroundColor Green }
            1 { Write-Host "→ 尚未注入。若载体在运行，explorer 重启后会补上；也可手动跑 run-manual。" -ForegroundColor Yellow }
            2 { Write-Host "→ 探测失败（找不到 explorer / 读内存失败）。" -ForegroundColor Red }
            3 { Write-Host "→ 环境错误（需要 64 位 Python，或拿不到 RVA）。" -ForegroundColor Red }
        }
    } else {
        Write-Host "(跳过：$verifier 或 Python 不可用)"
    }
}

# ---------------------------------------------------------------- 4. 日志
Section "4. 最近日志（$LogDir）"
foreach ($n in @('service.log', 'watermark-exe.log', 'rva-cache.log', 'symbol-check.log')) {
    $p = Join-Path $LogDir $n
    Write-Host ""
    Write-Host "[$n]" -ForegroundColor Yellow
    if (Test-Path $p) {
        Get-Content $p -Tail $Tail -Encoding UTF8 | ForEach-Object { Write-Host "  $_" }
    } else {
        Write-Host "  (不存在)"
    }
}

Write-Host ""
if ($cacheOk) { exit 0 }
exit 1
