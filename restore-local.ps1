[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$BackupPath,
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

$backup = Resolve-Path -LiteralPath $BackupPath -ErrorAction Stop
if ($backup.Path -notlike '*.dump.dpapi') { throw 'Restore requires a ThreatCommand .dump.dpapi backup.' }
$confirmation = Read-Host 'WARNING: Restore replaces the current local database. Type RESTORE to continue'
if ($confirmation -cne 'RESTORE') { Write-Output 'Restore cancelled.'; exit 0 }

$docker = Get-DockerCommand
& $docker info | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Docker Desktop is not ready.' }
$manifestPath = $backup.Path -replace '\.dump\.dpapi$', '.manifest.json'
if (Test-Path $manifestPath) {
  $manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
  $actualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $backup.Path).Hash
  if ($manifest.encrypted_sha256 -ne $actualHash) { throw 'Backup integrity check failed. The encrypted backup hash does not match its manifest.' }
}
else { throw 'Restore requires the matching .manifest.json so the encrypted-file hash and encryption parameters can be verified.' }

$temporaryDump = Join-Path $env:TEMP ("threatcommand-restore-" + [guid]::NewGuid().ToString() + '.dump')
$servicesStopped = $false
try {
  $encryptedBytes = [IO.File]::ReadAllBytes($backup.Path)
  $plainBytes = Unprotect-BackupPayload -EncryptedBytes $encryptedBytes -Manifest $manifest -BackupPassphrase $BackupPassphrase
  [IO.File]::WriteAllBytes($temporaryDump, $plainBytes)

  & $docker compose stop api worker frontend | Out-Null
  $servicesStopped = $true
  $containerId = (& $docker compose ps -q database).Trim()
  if (-not $containerId) { throw 'The local database container is not running.' }
  $containerDump = '/tmp/threatcommand-restore.dump'
  & $docker cp $temporaryDump "${containerId}:$containerDump"
  if ($LASTEXITCODE -ne 0) { throw 'Could not copy the restored dump into Docker.' }
  $restoreCommand = 'pg_restore --clean --if-exists --no-owner --exit-on-error -U "$POSTGRES_USER" -d "$POSTGRES_DB" ' + $containerDump
  & $docker compose exec -T database sh -c $restoreCommand
  if ($LASTEXITCODE -ne 0) { throw 'Database restore failed. The application remains stopped so you can inspect the error safely.' }
  & $docker compose exec -T database rm -f $containerDump | Out-Null
  Write-Output 'Restore completed. Starting local application services.'
}
finally {
  if ($encryptedBytes) { [Array]::Clear($encryptedBytes, 0, $encryptedBytes.Length) }
  if ($plainBytes) { [Array]::Clear($plainBytes, 0, $plainBytes.Length) }
  if (Test-Path $temporaryDump) { Remove-Item -LiteralPath $temporaryDump -Force }
  if ($servicesStopped) { & $docker compose up -d api worker frontend | Out-Null }
}
