# Backup and Restore Guide

## Create a backup

With Docker Desktop running, execute:

```powershell
.\backup-local.bat
```

This creates a PostgreSQL custom-format dump plus a SHA-256 integrity manifest under `data\backups`. When Windows DPAPI is available, the dump is protected for the current Windows user. If the PowerShell runtime cannot use DPAPI, the script securely prompts for a 12-character-or-longer backup passphrase and uses AES-256-CBC with HMAC-SHA-256 and PBKDF2-SHA-256 instead. Secrets and `.env` are intentionally excluded. Keep the backup passphrase in a password manager and store the backup with its manifest; backups are never uploaded automatically.

## Verify a backup without changing the live dashboard

Run a recovery drill after each important backup and before relying on a new ThreatCommand version:

```powershell
.\verify-backup-local.bat data\backups\threatcommand-YYYYMMDD-HHMMSS.dump.dpapi
```

The verifier checks the encrypted-file hash, decrypts with the same Windows user or backup passphrase used at creation, restores into a temporary isolated PostgreSQL database, checks the migration/connector/vulnerability counts, then removes that temporary database. It never stops services or changes the live `threatcommand` database. A local `.verification.json` report is written beside the backup.

## Restore a backup

Restoring replaces the database contents. Stop any active analysis work, make a fresh backup first, then run:

```powershell
.\restore-local.bat data\backups\threatcommand-YYYYMMDD-HHMMSS.dump.dpapi
```

The script displays a destructive-operation warning and requires a confirmation. Restore requires the same Windows user profile for DPAPI backups or the backup passphrase for the portable fallback. It requires and verifies the encrypted-file manifest, stops local application services, restores the database, then restarts services. Afterwards run `health-check.bat` and confirm the expected local records appear in the UI.

## Retention

Raw connector content has per-source retention and Settings shows local storage totals. Backups remain until you remove them. Keep only the recovery points you need and run the non-destructive verification drill periodically; reserve destructive restore drills for a planned maintenance window.
