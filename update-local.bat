@echo off
set "DOCKER=docker"
where docker >nul 2>&1
if errorlevel 1 (
  set "DOCKER=C:\Program Files\Docker\Docker\resources\bin\docker.exe"
  set "PATH=C:\Program Files\Docker\Docker\resources\bin;%PATH%"
)
echo This command may download updated container images and packages.
choice /M "Continue with update"
if errorlevel 2 exit /b 0
"%DOCKER%" compose pull
"%DOCKER%" compose up --build -d
echo Update finished. Run health-check.bat to verify services.
