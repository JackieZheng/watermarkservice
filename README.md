# ExplorerWatermarkService

Monitor explorer.exe restart and auto clear Win11 desktop watermark.

## Quick Start

1. **Install**: Double-click `install.bat` (requires admin, will auto-elevate)
2. **Uninstall**: Double-click `uninstall.bat`
3. **Check status**: Double-click `status.bat`

## Configuration

Edit `bin\config.json`:

```json
{
    "targetExe": "C:\\path\\to\\your\\program.exe",
    "checkInterval": 3,
    "logMaxLines": 2000
}
```

- `targetExe`: Program to execute when explorer restarts
- `checkInterval`: Check interval in seconds (default: 3)
- `logMaxLines`: Max log lines before auto-trim (default: 2000)

After editing config, restart the service:

```
tools\nssm.exe restart ExplorerWatermarkService
```

## File Structure

```
watermark-service/
  install.bat          - Install service (admin required)
  uninstall.bat        - Uninstall service (admin required)
  status.bat           - View service status and logs
  bin/
    monitor.ps1        - Core monitoring script
    config.json        - Configuration file
    service.log        - Runtime log (auto-generated)
  tools/
    nssm.exe           - Service manager (bundled)
```

## Service Management (manual)

```
tools\nssm.exe start ExplorerWatermarkService
tools\nssm.exe stop ExplorerWatermarkService
tools\nssm.exe restart ExplorerWatermarkService
tools\nssm.exe status ExplorerWatermarkService
tools\nssm.exe edit ExplorerWatermarkService
```

## How It Works

1. The service runs `monitor.ps1` in the background
2. Every 3 seconds it checks if explorer.exe has restarted
3. When a restart is detected, it executes the configured program
4. On first run, it also executes the program if explorer is already running

## Requirements

- Windows 10/11
- Administrator privileges (for install/uninstall only)