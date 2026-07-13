@echo off
set "DOCKER=docker"
where docker >nul 2>&1
if errorlevel 1 (
  set "DOCKER=C:\Program Files\Docker\Docker\resources\bin\docker.exe"
  set "PATH=C:\Program Files\Docker\Docker\resources\bin;%PATH%"
)
"%DOCKER%" compose down
echo ThreatCommand Local containers stopped. Local database data is preserved.
