[CmdletBinding()]
param(
  [System.Security.SecureString]$BackupPassphrase
)

$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

. (Join-Path $PSScriptRoot 'backup-crypto.ps1')

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
& $docker info | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Docker Desktop is not ready.' }

$backupDirectory = Join-Path $PSScriptRoot 'data\backups'
New-Item -ItemType Directory -Force -Path $backupDirectory | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$temporaryDump = Join-Path $backupDirectory "threatcommand-$stamp.restore-temp"
$encryptedBackup = Join-Path $backupDirectory "threatcommand-$stamp.dump.dpapi"
$manifestPath = Join-Path $backupDirectory "threatcommand-$stamp.manifest.json"
$containerId = (& $docker compose ps -q database).Trim()
if (-not $containerId) { throw 'The local database container is not running.' }
$containerDump = "/tmp/threatcommand-$stamp.dump"

try {
  $dumpCommand = 'pg_dump -Fc -U "$POSTGRES_USER" "$POSTGRES_DB" > ' + $containerDump
  & $docker compose exec -T database sh -c $dumpCommand
  if ($LASTEXITCODE -ne 0) { throw 'PostgreSQL dump creation failed.' }
  & $docker cp "${containerId}:$containerDump" $temporaryDump
  if ($LASTEXITCODE -ne 0) { throw 'Could not copy the local database dump from Docker.' }
  & $docker compose exec -T database rm -f $containerDump | Out-Null

  $plainBytes = [IO.File]::ReadAllBytes($temporaryDump)
  $backupPayload = Protect-BackupPayload -PlainBytes $plainBytes -BackupPassphrase $BackupPassphrase
  [IO.File]::WriteAllBytes($encryptedBackup, $backupPayload.encrypted_bytes)
  $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $encryptedBackup).Hash
  [pscustomobject]@{
    format = $backupPayload.format
    created_at = (Get-Date).ToUniversalTime().ToString('o')
    backup_file = (Split-Path -Leaf $encryptedBackup)
    encrypted_sha256 = $hash
    protection = $backupPayload.protection
    encryption = $backupPayload.encryption
    includes = 'PostgreSQL database only; secrets and .env are intentionally excluded.'
  } | ConvertTo-Json | Set-Content -LiteralPath $manifestPath -Encoding UTF8
  Write-Output "Encrypted local backup created: $encryptedBackup"
  Write-Output "Integrity manifest created: $manifestPath"
  Write-Output "Protection: $($backupPayload.protection)"
  Write-Output 'Store the backup and its manifest together in a location you control. Backups are never uploaded automatically.'
}
finally {
  if ($plainBytes) { [Array]::Clear($plainBytes, 0, $plainBytes.Length) }
  if (Test-Path $temporaryDump) { Remove-Item -LiteralPath $temporaryDump -Force }
  & $docker compose exec -T database rm -f $containerDump 2>$null | Out-Null
}
