# ExplorerWatermarkService - Monitor explorer.exe restart and auto clear Win11 watermark
# Version: 1.0.0

$serviceName = "ExplorerWatermarkService"
$targetProcess = "explorer"
$checkInterval = 3
$logMaxLines = 2000

# Read config
$configFile = Join-Path $PSScriptRoot "config.json"
if (Test-Path $configFile) {
    $cfg = Get-Content $configFile -Raw | ConvertFrom-Json
    $targetExe = Join-Path $PSScriptRoot $cfg.targetExe
    if ($cfg.checkInterval) { $checkInterval = $cfg.checkInterval }
    if ($cfg.logMaxLines) { $logMaxLines = $cfg.logMaxLines }
} else {
    Write-Host "[$serviceName] ERROR: config.json not found in $PSScriptRoot"
    exit 1
}

$logFile = Join-Path $PSScriptRoot "service.log"

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
        if ($lines -and $lines.Count -gt $logMaxLines) {
            $lines | Select-Object -Last $logMaxLines | Set-Content $logFile -Encoding UTF8
        }
    }
}

# Main loop
$lastStartTime = $null
$firstRun = $true

Write-Log "=========================================="
Write-Log "$serviceName started"
Write-Log "Target process : $targetProcess"
Write-Log "Target exe     : $targetExe"
Write-Log "Check interval : ${checkInterval}s"
Write-Log "=========================================="

if (-not (Test-Path $targetExe)) {
    Write-Log "ERROR: target exe not found: $targetExe"
}

while ($true) {
    try {
        $proc = Get-Process -Name $targetProcess -ErrorAction SilentlyContinue
        if ($proc) {
            $cur = $proc.StartTime
            if ($null -eq $lastStartTime) {
                $lastStartTime = $cur
                Write-Log "Detected $targetProcess running since $cur"
                if ($firstRun) {
                    Write-Log "First run - executing $targetExe"
                    Start-Process $targetExe
                    $firstRun = $false
                }
            } elseif ($cur -gt $lastStartTime) {
                Write-Log "Detected $targetProcess RESTART (was $lastStartTime, now $cur)"
                Write-Log "Executing $targetExe"
                Start-Process $targetExe
                $lastStartTime = $cur
            }
        } else {
            if ($null -ne $lastStartTime) {
                Write-Log "$targetProcess stopped - waiting for restart"
            }
            $lastStartTime = $null
        }
    } catch {
        Write-Log "Error: $_"
    }

    Start-Sleep -Seconds $checkInterval

    # Trim log every 100 iterations (~5 min)
    if (($script:iterCount = ($script:iterCount + 1) % 100) -eq 0) { Trim-Log }
}