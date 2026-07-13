@echo off
if "%~1"=="" (
  echo Usage: verify-backup-local.bat data\backups\threatcommand-YYYYMMDD-HHMMSS.dump.dpapi
  exit /b 1
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0verify-backup-local.ps1" -BackupPath "%~1"
