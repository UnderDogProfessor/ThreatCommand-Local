# Contributing to ThreatCommand Local

## Local development

1. Copy `.env.example` to `.env` and choose a unique local database password.
2. Start Docker Desktop, then run `start-local.bat` from the project root.
3. Run `health-check.bat` before and after a change.
4. Run backend tests with Docker:

   ```powershell
   $docker = 'C:\Program Files\Docker\Docker\resources\bin\docker.exe'
   $tests = (Resolve-Path backend\tests).Path
   & $docker compose run --rm --no-deps -v "${tests}:/app/tests:ro" api python -m unittest discover -s /app/tests -v
   ```

## Contribution boundaries

- Preserve localhost-only bindings, explicit network disclosures, and offline mode.
- Do not add real credentials, private case data, exports, backups, or `data/` contents to source control.
- New feed support needs source provenance, terms/use notes, parser tests, redirect/DNS safety checks, and a disabled-by-default connector.
- Detection changes must remain defensive and must not execute queries, payloads, or adversary behavior from this application.
- Document migrations and add tests for behavior that affects access control, import handling, source parsing, or data deletion.

## Before a pull request

Run the health check, backend unit tests, and a container build. The repository CI repeats these checks in a clean environment; it does not replace local review of source terms or a recovery drill.

For a release or public contribution, also run:

```powershell
.\security-check-local.bat
```
