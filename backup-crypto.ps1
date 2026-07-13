function Test-DpapiAvailable {
  try { Add-Type -AssemblyName System.Security.Cryptography.ProtectedData -ErrorAction Stop } catch { }
  return [bool]('System.Security.Cryptography.ProtectedData' -as [type])
}

function Join-BackupBytes {
  param([Parameter(Mandatory = $true)][byte[][]]$Arrays)
  $length = 0
  foreach ($array in $Arrays) { $length += $array.Length }
  $result = New-Object byte[] $length
  $offset = 0
  foreach ($array in $Arrays) {
    [Array]::Copy($array, 0, $result, $offset, $array.Length)
    $offset += $array.Length
  }
  return $result
}

function Test-BackupBytesEqual {
  param([byte[]]$Left, [byte[]]$Right)
  if ($Left.Length -ne $Right.Length) { return $false }
  $difference = 0
  for ($index = 0; $index -lt $Left.Length; $index++) { $difference = $difference -bor ($Left[$index] -bxor $Right[$index]) }
  return $difference -eq 0
}

function ConvertFrom-BackupSecureString {
  param([Parameter(Mandatory = $true)][System.Security.SecureString]$Value)
  $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Value)
  try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer) }
  finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
}

function Get-BackupPassphraseText {
  param([System.Security.SecureString]$BackupPassphrase, [switch]$Confirm)
  if ($null -eq $BackupPassphrase) {
    $BackupPassphrase = Read-Host 'Backup encryption passphrase' -AsSecureString
    if ($Confirm) {
      $second = Read-Host 'Confirm backup encryption passphrase' -AsSecureString
      $firstText = ConvertFrom-BackupSecureString $BackupPassphrase
      $secondText = ConvertFrom-BackupSecureString $second
      if ($firstText -cne $secondText) { throw 'The backup encryption passphrases did not match.' }
      return $firstText
    }
  }
  return ConvertFrom-BackupSecureString $BackupPassphrase
}

function Get-BackupKeyMaterial {
  param([Parameter(Mandatory = $true)][string]$Passphrase, [Parameter(Mandatory = $true)][byte[]]$Salt, [int]$Iterations = 600000)
  $passwordBytes = [Text.Encoding]::UTF8.GetBytes($Passphrase)
  try {
    $derive = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($passwordBytes, $Salt, $Iterations, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    try { return $derive.GetBytes(64) }
    finally { $derive.Dispose() }
  }
  finally { [Array]::Clear($passwordBytes, 0, $passwordBytes.Length) }
}

function Protect-BackupPayload {
  param([Parameter(Mandatory = $true)][byte[]]$PlainBytes, [System.Security.SecureString]$BackupPassphrase)
  if (Test-DpapiAvailable) {
    $entropy = [Text.Encoding]::UTF8.GetBytes('ThreatCommand Local backup format v1')
    return [pscustomobject]@{
      encrypted_bytes = [System.Security.Cryptography.ProtectedData]::Protect($PlainBytes, $entropy, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
      format = 'threatcommand-dpapi-v1'
      protection = 'Windows DPAPI CurrentUser; restore requires the same Windows user profile.'
      encryption = $null
    }
  }

  $passphrase = Get-BackupPassphraseText -BackupPassphrase $BackupPassphrase -Confirm
  if ($passphrase.Length -lt 12) { throw 'The backup encryption passphrase must contain at least 12 characters.' }
  $salt = New-Object byte[] 16; [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($salt)
  $iv = New-Object byte[] 16; [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($iv)
  $material = Get-BackupKeyMaterial -Passphrase $passphrase -Salt $salt
  $encryptionKey = [byte[]]$material[0..31]
  $macKey = [byte[]]$material[32..63]
  try {
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.KeySize = 256; $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC; $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.Key = $encryptionKey; $aes.IV = $iv
    try { $ciphertext = $aes.CreateEncryptor().TransformFinalBlock($PlainBytes, 0, $PlainBytes.Length) }
    finally { $aes.Dispose() }
    $authenticated = Join-BackupBytes @([Text.Encoding]::UTF8.GetBytes('threatcommand-password-backup-v1'), $salt, $iv, $ciphertext)
    $hmac = [System.Security.Cryptography.HMACSHA256]::new($macKey)
    try { $mac = $hmac.ComputeHash($authenticated) }
    finally { $hmac.Dispose(); [Array]::Clear($authenticated, 0, $authenticated.Length) }
    return [pscustomobject]@{
      encrypted_bytes = $ciphertext
      format = 'threatcommand-password-aes-cbc-hmac-v1'
      protection = 'AES-256-CBC with HMAC-SHA-256 and PBKDF2-SHA-256; restore requires the backup encryption passphrase.'
      encryption = [ordered]@{ scheme = 'aes-256-cbc-hmac-sha256'; kdf = 'pbkdf2-sha256'; iterations = 600000; salt_b64 = [Convert]::ToBase64String($salt); iv_b64 = [Convert]::ToBase64String($iv); mac_b64 = [Convert]::ToBase64String($mac) }
    }
  }
  finally { [Array]::Clear($material, 0, $material.Length); [Array]::Clear($encryptionKey, 0, $encryptionKey.Length); [Array]::Clear($macKey, 0, $macKey.Length) }
}

function Unprotect-BackupPayload {
  param([Parameter(Mandatory = $true)][byte[]]$EncryptedBytes, [Parameter(Mandatory = $true)]$Manifest, [System.Security.SecureString]$BackupPassphrase)
  $scheme = if ($Manifest.PSObject.Properties.Name -contains 'encryption' -and $null -ne $Manifest.encryption) { $Manifest.encryption.scheme } else { '' }
  if ($scheme -eq 'aes-256-cbc-hmac-sha256') {
    $passphrase = Get-BackupPassphraseText -BackupPassphrase $BackupPassphrase
    $iterations = [int]$Manifest.encryption.iterations
    $salt = [Convert]::FromBase64String($Manifest.encryption.salt_b64)
    $iv = [Convert]::FromBase64String($Manifest.encryption.iv_b64)
    $expectedMac = [Convert]::FromBase64String($Manifest.encryption.mac_b64)
    $material = Get-BackupKeyMaterial -Passphrase $passphrase -Salt $salt -Iterations $iterations
    $encryptionKey = [byte[]]$material[0..31]
    $macKey = [byte[]]$material[32..63]
    try {
      $authenticated = Join-BackupBytes @([Text.Encoding]::UTF8.GetBytes('threatcommand-password-backup-v1'), $salt, $iv, $EncryptedBytes)
      $hmac = [System.Security.Cryptography.HMACSHA256]::new($macKey)
      try { $actualMac = $hmac.ComputeHash($authenticated) }
      finally { $hmac.Dispose(); [Array]::Clear($authenticated, 0, $authenticated.Length) }
      if (-not (Test-BackupBytesEqual $expectedMac $actualMac)) { throw 'Backup passphrase or authenticated encryption check failed.' }
      $aes = [System.Security.Cryptography.Aes]::Create()
      $aes.KeySize = 256; $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC; $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
      $aes.Key = $encryptionKey; $aes.IV = $iv
      try { return $aes.CreateDecryptor().TransformFinalBlock($EncryptedBytes, 0, $EncryptedBytes.Length) }
      finally { $aes.Dispose() }
    }
    finally { [Array]::Clear($material, 0, $material.Length); [Array]::Clear($encryptionKey, 0, $encryptionKey.Length); [Array]::Clear($macKey, 0, $macKey.Length) }
  }
  if (-not (Test-DpapiAvailable)) { throw 'This PowerShell runtime cannot use Windows DPAPI. This backup was not created with the portable passphrase fallback.' }
  $entropy = [Text.Encoding]::UTF8.GetBytes('ThreatCommand Local backup format v1')
  return [System.Security.Cryptography.ProtectedData]::Unprotect($EncryptedBytes, $entropy, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
}
