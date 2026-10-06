@echo off
rem ---------------------------------------------------------------------------
rem  Guarded launcher for ClearWinWatermark.exe        (ASCII only, NO BOM)
rem
rem  IMPORTANT: keep this file ASCII and WITHOUT a UTF-8 BOM.
rem  cmd.exe does not understand a BOM: the first line becomes garbage, the
rem  '@echo off' never takes effect and cmd prints
rem      '<BOM>@echo' is not recognized as an internal or external command
rem  plus every command gets echoed. Same rule applies to any .cmd/.bat here.
rem
rem  ClearWinWatermark.exe (UWD2) downloads shell32.pdb from the Microsoft public
rem  symbol server on every start. On Windows Insider preview builds (and right
rem  after a cumulative update) those symbols are not published yet, so the
rem  download always fails with HTTP 404 and the tool panics:
rem      PDB not found. Fetching...
rem      thread 'main' panicked at src\fetch_pdb.rs:8:47 ... Status(404, ...)
rem
rem  This wrapper pre-warms / validates the RVA cache first (including migration
rem  from a neighbouring published build when this build's symbols are missing)
rem  and only launches the original executable when a trustworthy RVA exists.
rem  The exe itself is NOT modified.
rem
rem  Layout-agnostic: this file only assumes that "<its own folder>/../" is the
rem  install root, so it can be dropped into any folder name without edits.
rem  The target is read from config.json next to this file.
rem
rem  Any arguments are forwarded, for example:
rem      clear-watermark.cmd -CheckOnly   validate the cache only, do not inject
rem      clear-watermark.cmd -Force       skip every check, inject directly
rem ---------------------------------------------------------------------------
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0run-watermark-guarded.ps1" %*
exit /b %ERRORLEVEL%
