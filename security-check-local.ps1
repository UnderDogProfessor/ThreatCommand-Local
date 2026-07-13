[CmdletBinding()]
param(
  [switch]$SkipDependencyAudit
)

$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

function Get-DockerCommand {
  $directory = 'C:\Program Files\Docker\Docker\resources\bin'
  if ((Test-Path $directory) -and $env:PATH -notlike "*$directory*") { $env:PATH = "$directory;$env:PATH" }
  $candidate = 'docker'
  if (Get-Command $candidate -ErrorAction SilentlyContinue) { return $candidate }
  $fallback = Join-Path $directory 'docker.exe'
  if (Test-Path $fallback) { return $fallback }
  throw 'Docker CLI was not found. Start Docker Desktop, then retry.'
}

$docker = Get-DockerCommand
& $docker compose config --quiet
if ($LASTEXITCODE -ne 0) { throw 'Docker Compose configuration validation failed.' }

$excluded = @('data', 'node_modules', '.next', '.git')
$sourceFiles = Get-ChildItem -Recurse -File | Where-Object {
  $relative = $_.FullName.Substring($PSScriptRoot.Length).TrimStart('\')
  -not ($excluded | Where-Object { $relative -like "$_\*" }) -and
  $_.Name -notin @('.env', 'package-lock.json')
}
$secretPatterns = @(
  'sk-[A-Za-z0-9_-]{20,}',
  'AKIA[0-9A-Z]{16}',
  '-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----'
)
foreach ($pattern in $secretPatterns) {
  $match = $sourceFiles | Select-String -Pattern $pattern -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($match) { throw "Potential secret pattern found in $($match.Path). Remove it before publishing." }
}

if (-not $SkipDependencyAudit) {
  $frontend = (Resolve-Path frontend).Path
  $frontendAuditCommand = 'npm ci --ignore-scripts --no-audit --no-fund && npm audit --omit=dev --audit-level=high; audit_status=$?; rm -rf node_modules; exit $audit_status'
  & $docker run --rm -v "${frontend}:/workspace" -w /workspace node:24-alpine@sha256:a0b9bf06e4e6193cf7a0f58816cc935ff8c2a908f81e6f1a95432d679c54fbfd sh -c $frontendAuditCommand
  if ($LASTEXITCODE -ne 0) { throw 'Frontend dependency audit reported a high-severity or greater issue.' }
  & $docker compose run --rm --no-deps api python -m pip check
  if ($LASTEXITCODE -ne 0) { throw 'Backend dependency consistency check failed.' }
}

if ($SkipDependencyAudit) {
  Write-Output 'Security baseline passed: Compose configuration and source secret-pattern scan are clean. Dependency audit was skipped by request.'
}
else {
  Write-Output 'Security baseline passed: Compose configuration, source secret-pattern scan, and dependency checks are clean.'
}
