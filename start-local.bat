@echo off
setlocal
set "DOCKER=docker"
where docker >nul 2>&1
if errorlevel 1 (
  set "DOCKER=C:\Program Files\Docker\Docker\resources\bin\docker.exe"
  set "PATH=C:\Program Files\Docker\Docker\resources\bin;%PATH%"
)
if not exist .env (
  copy /Y .env.example .env >nul
  for /f "delims=" %%P in ('powershell -NoProfile -Command "$bytes=New-Object byte[] 32; [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes); [Convert]::ToBase64String($bytes).Replace('/','-').Replace('+','_').TrimEnd('=')"') do set "TC_DB_PASSWORD=%%P"
  powershell -NoProfile -Command "$path=Join-Path $PWD '.env'; $value=$env:TC_DB_PASSWORD; (Get-Content -LiteralPath $path | ForEach-Object { if ($_ -match '^POSTGRES_PASSWORD=') { 'POSTGRES_PASSWORD=' + $value } else { $_ } }) | Set-Content -LiteralPath $path -Encoding UTF8"
  set "TC_DB_PASSWORD="
  echo Created .env with a unique local database password.
)
"%DOCKER%" info >nul 2>&1
if errorlevel 1 (
  echo Docker Desktop is not ready. Open Docker Desktop, wait for it to finish starting, then run this script again.
  exit /b 1
)
echo Starting ThreatCommand Local services on localhost only...
"%DOCKER%" compose up --build -d
if errorlevel 1 exit /b 1
echo.
echo ThreatCommand Local is starting at http://127.0.0.1:3000
echo Local API documentation: http://127.0.0.1:8000/docs
echo Use health-check.bat to verify readiness.
