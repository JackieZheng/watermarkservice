<#
.SYNOPSIS
  检查当前系统的 shell32.pdb 是否已发布到微软公共符号服务器（msdl）。

.DESCRIPTION
  背景：tools\ClearWinWatermark.exe（UWD2）启动后会从 msdl 下载 shell32.pdb，
  再从 PDB 里按符号取到函数 RVA，最后把 RET 注入 explorer.exe 去掉桌面水印。
  如果当前 Windows 版本的符号还没被微软发布（Insider 预览版、刚打补丁的版本都会这样），
  这个请求必然返回 404，程序会直接 panic 退出：
      PDB not found. Fetching...
      thread 'main' panicked at src\fetch_pdb.rs:8:47 ... Status(404, ...)

  本脚本做两件事：
    1) 读取本机 shell32.dll 调试目录里的 CodeView(RSDS) 信息，算出 PDB 名 / GUID / Age，
       拼出符号服务器 URL（拼法与 exe 内部完全一致：GUID 前 3 段按小端数值格式化 + Age 十六进制，不带 0x）；
    2) 对该 URL 发 HEAD 请求探测可用性（200/301/302/307 = 符号已发布；404 = 尚未发布）。

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File bin\check-symbols.ps1

.EXAMPLE
  # 每 30 分钟探测一次，符号一上线就自动运行 ClearWinWatermark.exe
  powershell -NoProfile -ExecutionPolicy Bypass -File bin\check-symbols.ps1 -Watch -IntervalMinutes 30 -RunOnAvailable

.NOTES
  退出码：0 = 符号已发布可用；1 = 符号未发布(404)；2 = 脚本自身出错（文件/网络等）。
#>
[CmdletBinding()]
param(
    # 要检查的本地 PE 文件（默认 shell32.dll，即 exe 需要的那个 PDB）
    [string] $Target = "$env:SystemRoot\System32\shell32.dll",
    # 符号服务器地址
    [string] $Server = "https://msdl.microsoft.com/download/symbols",
    # 单次请求超时（秒）
    [int]    $TimeoutSec = 25,
    # 持续轮询模式
    [switch] $Watch,
    # 轮询间隔（分钟），配合 -Watch
    [int]    $IntervalMinutes = 30,
    # 探测到符号可用时，立即运行目标 exe（配合 -Exe）
    [switch] $RunOnAvailable,
    # 目标 exe 路径（默认上级目录 tools\ClearWinWatermark.exe）
    [string] $Exe = "",
    # 日志目录（默认上级目录 log\）
    [string] $LogDir = "",
    # 不写 log\symbol-check.log
    [switch] $NoLog
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------- 日志
$rootDir = Split-Path $PSScriptRoot -Parent
if (-not $LogDir) { $LogDir = Join-Path $rootDir 'log' }
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
$logFile = Join-Path $LogDir 'symbol-check.log'

function Write-CheckLog {
    param([string] $Message)
    if ($NoLog) { return }
    $entry = "[{0}] {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
    Add-Content -Path $logFile -Value $entry -Encoding UTF8
}

# ---------------------------------------------------------------- PE / CodeView 解析
function Get-CodeViewIndex {
    param(
        [string] $Path,
        [string] $Server
    )

    if (-not (Test-Path $Path)) { throw "找不到文件: $Path" }
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -lt 0x100 -or $bytes[0] -ne 0x4D -or $bytes[1] -ne 0x5A) { throw "不是有效的 PE 文件: $Path" }

    $peOff   = [BitConverter]::ToInt32($bytes, 0x3C)
    $coff    = $peOff + 4
    $numSec  = [BitConverter]::ToUInt16($bytes, $coff + 2)
    $sizeOpt = [BitConverter]::ToUInt16($bytes, $coff + 16)
    $optOff  = $coff + 20
    $magic   = [BitConverter]::ToUInt16($bytes, $optOff)

    if ($magic -eq 0x20B) { $ddOff = $optOff + 112 }        # PE32+
    elseif ($magic -eq 0x10B) { $ddOff = $optOff + 96 }     # PE32
    else { throw ("未知的 OptionalHeader magic: 0x{0:X}" -f $magic) }

    # DataDirectory[6] = 调试目录
    $dbgRva  = [BitConverter]::ToUInt32($bytes, $ddOff + 6 * 8)
    $dbgSize = [BitConverter]::ToUInt32($bytes, $ddOff + 6 * 8 + 4)
    if ($dbgRva -eq 0) { throw "该文件没有调试目录（debug directory），无法定位 PDB。" }

    $secOff   = $optOff + $sizeOpt
    $sections = New-Object System.Collections.ArrayList
    for ($i = 0; $i -lt $numSec; $i++) {
        $o = $secOff + $i * 40
        [void]$sections.Add([pscustomobject]@{
            VirtualAddress   = [BitConverter]::ToUInt32($bytes, $o + 12)
            VirtualSize      = [BitConverter]::ToUInt32($bytes, $o + 8)
            SizeOfRawData    = [BitConverter]::ToUInt32($bytes, $o + 16)
            PointerToRawData = [BitConverter]::ToUInt32($bytes, $o + 20)
        })
    }

    $dbgOff = -1
    foreach ($s in $sections) {
        $span = [Math]::Max($s.VirtualSize, $s.SizeOfRawData)
        if ($dbgRva -ge $s.VirtualAddress -and $dbgRva -lt ($s.VirtualAddress + $span)) {
            $dbgOff = $s.PointerToRawData + ($dbgRva - $s.VirtualAddress)
            break
        }
    }
    if ($dbgOff -lt 0) { throw "调试目录 RVA 无法映射到文件偏移。" }

    for ($i = 0; $i -lt [int]($dbgSize / 28); $i++) {
        $o    = $dbgOff + $i * 28
        $type = [BitConverter]::ToUInt32($bytes, $o + 12)
        $size = [BitConverter]::ToUInt32($bytes, $o + 16)
        $rva  = [BitConverter]::ToUInt32($bytes, $o + 20)
        $ptr  = [BitConverter]::ToUInt32($bytes, $o + 24)
        if ($type -ne 2) { continue }                       # 2 = IMAGE_DEBUG_TYPE_CODEVIEW

        $dataOff = -1
        if ($rva -ne 0) {
            foreach ($s in $sections) {
                $span = [Math]::Max($s.VirtualSize, $s.SizeOfRawData)
                if ($rva -ge $s.VirtualAddress -and $rva -lt ($s.VirtualAddress + $span)) {
                    $dataOff = $s.PointerToRawData + ($rva - $s.VirtualAddress)
                    break
                }
            }
        } elseif ($ptr -ne 0) {
            $dataOff = [int]$ptr
        }
        if ($dataOff -lt 0 -or ($dataOff + 28) -gt $bytes.Length) { continue }
        if ($bytes[$dataOff] -ne 0x52 -or $bytes[$dataOff + 1] -ne 0x53 -or
            $bytes[$dataOff + 2] -ne 0x44 -or $bytes[$dataOff + 3] -ne 0x53) { continue }   # 'RSDS'

        $guidBytes = $bytes[($dataOff + 4)..($dataOff + 19)]
        $age       = [BitConverter]::ToUInt32($bytes, $dataOff + 20)

        $end = $dataOff + 24
        while ($end -lt $bytes.Length -and $bytes[$end] -ne 0) { $end++ }
        $pdbName = [System.Text.Encoding]::ASCII.GetString($bytes, $dataOff + 24, $end - $dataOff - 24)

        # 符号服务器路径：GUID 前 3 段按小端数值写，其余按字节顺序写，后面紧跟十六进制 Age（无 0x、不补零）
        $d1   = [BitConverter]::ToUInt32($guidBytes, 0)
        $d2   = [BitConverter]::ToUInt16($guidBytes, 4)
        $d3   = [BitConverter]::ToUInt16($guidBytes, 6)
        $tail = (($guidBytes[8..15]) | ForEach-Object { $_.ToString('X2') }) -join ''
        $guid = '{0:X8}-{1:X4}-{2:X4}-{3}' -f $d1, $d2, $d3, $tail
        $index = ('{0:X8}{1:X4}{2:X4}{3}' -f $d1, $d2, $d3, $tail) + $age.ToString('X')

        return [pscustomobject]@{
            File    = $Path
            PdbName = $pdbName
            Guid    = $guid
            Age     = $age
            Index   = $index
            Url     = "$Server/$pdbName/$index/$pdbName"
        }
    }
    throw "在 $Path 的调试目录里没找到 CodeView(RSDS) 记录。"
}

# ---------------------------------------------------------------- HTTP 探测（不跟随跳转，302 也算命中）
function Test-SymbolUrl {
    param(
        [string] $Url,
        [int]    $TimeoutSec = 25
    )
    $req = [System.Net.HttpWebRequest]::Create($Url)
    $req.Method            = 'HEAD'
    $req.AllowAutoRedirect = $false
    $req.Timeout           = $TimeoutSec * 1000
    $req.UserAgent         = 'Microsoft-Symbol-Server'
    try {
        $proxy = [System.Net.WebRequest]::GetSystemWebProxy()
        if ($proxy) { $req.Proxy = $proxy }
    } catch { }
    try {
        $resp = $req.GetResponse()
        $code = [int]$resp.StatusCode
        $resp.Close()
        return $code
    } catch [System.Net.WebException] {
        if ($_.Exception.Response) { return [int]$_.Exception.Response.StatusCode }
        return -1
    }
}

# ---------------------------------------------------------------- 主流程
if (-not $Exe) { $Exe = Join-Path $rootDir 'tools\ClearWinWatermark.exe' }

$osKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$build = try { (Get-ItemProperty $osKey) } catch { $null }

do {
    try {
        $info = Get-CodeViewIndex -Path $Target -Server $Server
        $code = Test-SymbolUrl -Url $info.Url -TimeoutSec $TimeoutSec
        $ok   = ($code -eq 200 -or $code -eq 301 -or $code -eq 302 -or $code -eq 307)

        Write-Output ("OS build      : {0}.{1} ({2})" -f $build.CurrentBuild, $build.UBR, $build.BuildLabEx)
        Write-Output ("Target file   : {0}" -f $info.File)
        Write-Output ("PDB name      : {0}" -f $info.PdbName)
        Write-Output ("PDB GUID      : {0}  Age={1}" -f $info.Guid, $info.Age)
        Write-Output ("Symbol index  : {0}" -f $info.Index)
        Write-Output ("Symbol URL    : {0}" -f $info.Url)
        Write-Output ("HTTP status   : {0}" -f $code)
        if ($ok) {
            Write-Output "VERDICT       : SYMBOLS AVAILABLE  -> ClearWinWatermark.exe 可以正常工作"
        } else {
            Write-Output "VERDICT       : SYMBOLS MISSING    -> 微软公共符号服务器上还没有该版本的 PDB"
            Write-Output "                 (ClearWinWatermark.exe 会 panic 退出：fetch_pdb.rs 404 unwrap)"
        }

        Write-CheckLog ("build={0}.{1} file={2} pdb={3} index={4} http={5} verdict={6}" -f `
            $build.CurrentBuild, $build.UBR, $info.File, $info.PdbName, $info.Index, $code, $(if ($ok) { 'AVAILABLE' } else { 'MISSING' }))

        if ($ok) {
            if ($RunOnAvailable) {
                if (Test-Path $Exe) {
                    Start-Process -FilePath $Exe -WindowStyle Hidden
                    Write-Output ("EXECUTED      : {0}" -f $Exe)
                    Write-CheckLog ("--RunOnAvailable: launched {0}" -f $Exe)
                } else {
                    Write-Output ("ERROR         : 找不到 {0}" -f $Exe)
                    Write-CheckLog ("--RunOnAvailable: exe not found: {0}" -f $Exe)
                }
            }
            exit 0
        }

        if (-not $Watch) { exit 1 }
        Write-Output ("WAIT          : 每 {0} 分钟重试一次，Ctrl+C 退出" -f $IntervalMinutes)
        Start-Sleep -Seconds ($IntervalMinutes * 60)
    }
    catch {
        Write-Output ("ERROR         : {0}" -f $_.Exception.Message)
        Write-CheckLog ("ERROR: {0}" -f $_.Exception.Message)
        exit 2
    }
} while ($true)
