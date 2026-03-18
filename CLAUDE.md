# ZFP Test Script

Diagnostic PowerShell script that validates whether a Windows target machine meets every requirement for Flexera's **Zero Footprint Agentless (ZFP/ZFA)** inventory scanning — simulating what a real Flexera Beacon does.

## Language Constraints (Critical)

- **PowerShell 5.1 only** — no PS 7 features
- No null-coalescing (`??`), ternary (`?:`), or null-conditional (`?.`) operators
- No `ForEach-Object -Parallel` — use `Start-Job` for parallelism
- **DCOM only** for remote execution — never WinRM/WSMan (`New-CimSession` with DCOM transport is fine; `Enter-PSSession`/`Invoke-Command` are not)
- **No IPv6** — targets are IPv4 only

## Architecture

Single-script design: `ZFP_Test_Script.ps1`

- All user config lives in `#region USER CONFIGURATION` at the top — no external config files
- Results are stored in `$Script:Results` as `[PSCustomObject]` with fields: `Category`, `Test`, `Result`, `Detail`, `Hint`
- Console output: colour-coded `PASS` / `WARN` / `FAIL` / `INFO` / `SKIP`
- Reports saved to `$ReportOutputDir` as HTML (dark-themed) or CSV fallback

## What Each Section Tests

| Section | Tests |
|---------|-------|
| 1 — Local Reachability | DNS, ICMP, TCP 135 (RPC/DCOM), TCP 445 (SMB) |
| 2 — SMB / Admin$ | Admin$ read/write, C$ access |
| 3 — Remote Execution | DCOM CIM session, `Win32_Process.Create` smoke test |
| 4 — Target-Side Checks | Target resolves Beacon name, reads `ndtrack.exe` via UNC, reaches ManageSoftRL HTTP |
| 5 — ndtrack Execution | UNC launch of `ndtrack.exe` (Beacon-style), optional local staged run |
| 6 — tracker.log Tail | Last 20 lines of Flexera tracker log from target |

## Multi-Target / CSV Mode

Set `$RunMode = 'Csv'` and `$TargetCsvPath`. Parallelism via `Start-Job` (max `$MaxParallelJobs`, recommended 3–5). Credentials serialised once via DPAPI (`ConvertFrom-SecureString` with no key) — no per-target re-prompting.

## Known Gotcha

ndtrack launched via `Win32_Process.Create` may fail to upload even when a real beacon scan succeeds. The Beacon uses `mgsreservice.exe` running as SYSTEM, giving a different security/network context. Use Section 6 (tracker.log tail) to distinguish test-context artefact from genuine failure.

## Running

```powershell
# Elevated PowerShell 5.1
.\ZFP_Test_Script.ps1
```

Reports saved to `C:\Diag\ZFP Reports\` by default (prompted on first run).

## Related Repos

- [Flexera_PreReq_Check](https://github.com/ultimateunraid/Flexera_PreReq_Check) — TLS/.NET/Flexera One connectivity checks
- [PreReq_Snow](https://github.com/ultimateunraid/PreReq_Snow) — TLS cipher suites/.NET/Snow Atlas connectivity checks
