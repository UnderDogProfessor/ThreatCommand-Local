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
if ($backup.Path -notlike '*.dump.dpapi') { throw 'Verification requires a ThreatCommand .dump.dpapi backup.' }
$manifestPath = $backup.Path -replace '\.dump\.dpapi$', '.manifest.json'
if (-not (Test-Path $manifestPath)) { throw 'Verification requires the matching .manifest.json so the encrypted-file hash can be checked first.' }

$manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
$actualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $backup.Path).Hash
if ($manifest.encrypted_sha256 -ne $actualHash) { throw 'Backup integrity check failed. The encrypted backup hash does not match its manifest.' }

$docker = Get-DockerCommand
& $docker info | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Docker Desktop is not ready.' }

$temporaryDump = Join-Path $env:TEMP ('threatcommand-verify-' + [guid]::NewGuid().ToString() + '.dump')
$containerDump = '/tmp/threatcommand-verify.dump'
$verificationDatabase = 'threatcommand_verify_' + [guid]::NewGuid().ToString('N').Substring(0, 12)
$containerId = ''
$databaseCreated = $false
$verification = [ordered]@{
  format = 'threatcommand-backup-verification-v1'
  verified_at = (Get-Date).ToUniversalTime().ToString('o')
  backup_file = (Split-Path -Leaf $backup.Path)
  encrypted_sha256 = $actualHash
  live_database_changed = $false
  success = $false
  verification_database = $verificationDatabase
  schema_migrations = $null
  connector_count = $null
  vulnerability_count = $null
}
$reportPath = Join-Path (Split-Path -Parent $backup.Path) (((Split-Path -Leaf $backup.Path) -replace '\.dump\.dpapi$', '') + '.verification.json')

try {
  $encryptedBytes = [IO.File]::ReadAllBytes($backup.Path)
  $plainBytes = Unprotect-BackupPayload -EncryptedBytes $encryptedBytes -Manifest $manifest -BackupPassphrase $BackupPassphrase
  [IO.File]::WriteAllBytes($temporaryDump, $plainBytes)

  $containerId = (& $docker compose ps -q database).Trim()
  if (-not $containerId) { throw 'The local database container is not running.' }
  & $docker cp $temporaryDump "${containerId}:$containerDump"
  if ($LASTEXITCODE -ne 0) { throw 'Could not copy the decrypted verification dump into Docker.' }

  $createCommand = "psql -v ON_ERROR_STOP=1 -U `$POSTGRES_USER -d postgres -c 'CREATE DATABASE $verificationDatabase'"
  & $docker compose exec -T database sh -c $createCommand
  if ($LASTEXITCODE -ne 0) { throw 'Could not create the isolated verification database.' }
  $databaseCreated = $true

  $restoreCommand = "pg_restore --no-owner --exit-on-error -U `$POSTGRES_USER -d $verificationDatabase $containerDump"
  & $docker compose exec -T database sh -c $restoreCommand
  if ($LASTEXITCODE -ne 0) { throw 'The backup could not be restored into the isolated verification database.' }

  $countCommand = "psql -At -v ON_ERROR_STOP=1 -U `$POSTGRES_USER -d $verificationDatabase -c 'SELECT (SELECT count(*) FROM schema_migrations), (SELECT count(*) FROM connectors), (SELECT count(*) FROM vulnerabilities);'"
  $counts = (& $docker compose exec -T database sh -c $countCommand).Trim().Split('|')
  if ($LASTEXITCODE -ne 0 -or $counts.Count -ne 3) { throw 'The isolated restored database did not return its verification counts.' }
  $verification.schema_migrations = [int]$counts[0]
  $verification.connector_count = [int]$counts[1]
  $verification.vulnerability_count = [int]$counts[2]
  $verification.success = $true
  Write-Output "Backup verification passed: restored into isolated database $verificationDatabase, then scheduled for removal."
}
catch {
  $verification.error = $_.Exception.Message
  throw
}
finally {
  if ($containerId) {
    & $docker compose exec -T database rm -f $containerDump 2>$null | Out-Null
    if ($databaseCreated) {
      $dropCommand = "psql -v ON_ERROR_STOP=1 -U `$POSTGRES_USER -d postgres -c 'DROP DATABASE IF EXISTS $verificationDatabase WITH (FORCE)'"
      & $docker compose exec -T database sh -c $dropCommand 2>$null | Out-Null
    }
  }
  if (Test-Path $temporaryDump) { Remove-Item -LiteralPath $temporaryDump -Force }
  if ($encryptedBytes) { [Array]::Clear($encryptedBytes, 0, $encryptedBytes.Length) }
  if ($plainBytes) { [Array]::Clear($plainBytes, 0, $plainBytes.Length) }
  $verification | ConvertTo-Json | Set-Content -LiteralPath $reportPath -Encoding UTF8
  Write-Output "Verification report: $reportPath"
}
