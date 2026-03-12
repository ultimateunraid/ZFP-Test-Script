# ZFP Test Script

A PowerShell 5.1 diagnostic tool that validates whether a Windows target machine meets every requirement for Flexera's **Zero Footprint Agentless (ZFA/ZFP)** inventory scanning — before you ever run a real scan.

---

## What It Does

The script simulates the exact checks a Flexera Beacon performs during a ZFP scan:

| Section | What is tested |
|---------|---------------|
| **1 — Local Reachability** | DNS resolution, ICMP (informational), TCP 135 (RPC/DCOM), TCP 445 (SMB) |
| **2 — SMB / Admin$** | Admin$ read/write, C$ share access |
| **3 — Remote Execution** | DCOM CIM session, `Win32_Process.Create` smoke test |
| **4 — Target-Side Checks** | Target resolves Beacon hostname, target can read `ndtrack.exe` via UNC, target can reach ManageSoftRL HTTP endpoint |
| **5 — ndtrack Execution** | UNC launch of `ndtrack.exe` (Beacon-style), optional local staged run |
| **6 — tracker.log Tail** | Reads last 20 lines of the Flexera tracker log from the target |

Results are colour-coded in the console (`PASS` / `WARN` / `FAIL` / `INFO` / `SKIP`) with remediation hints for every failure. An HTML or CSV report is saved automatically.

> **DCOM only** — WinRM/WSMan is intentionally not used. The Flexera Beacon uses `Win32_Process.Create` over DCOM and a WinRM-only pass would be a false positive.

---

## Requirements

- PowerShell **5.1** (not PS 7 — script uses PS 5.1-compatible syntax throughout)
- Run **elevated** (As Administrator) on the machine performing the diagnostic
- The account running the script must have local admin rights on the target, or a credential with those rights must be supplied
- Network access from the script host to the target on TCP 135 and TCP 445

---

## Quick Start

1. Open the `USER CONFIGURATION` block at the top of the script
2. Set `$TargetComputer`, `$BeaconHostname`, `$UploadServer`, and `$CredentialUsername`
3. Run elevated in PowerShell 5.1:

```powershell
.\ZFP_Test_Script.ps1
```

An HTML report is saved automatically to `C:\Diag\ZFP Reports\` (you will be asked to confirm directory creation on first run).

---

## Configuration Reference

All user-editable settings are in the `#region USER CONFIGURATION` block at the top of the script.

### Target & Beacon

| Variable | Description | Default |
|----------|-------------|---------|
| `$TargetComputer` | Hostname, FQDN, or IP of the Windows machine to scan | `WORKSTATION01` |
| `$BeaconHostname` | Hostname/IP of the Flexera Beacon hosting `mgsRET$` | `BEACON01` |
| `$UploadServer` | Server hosting `ManageSoftRL` | `BEACON01` |
| `$UploadProtocol` | `http` or `https` | `http` |
| `$UploadPort` | Port (default 80/443 are omitted from the URL automatically) | `80` |
| `$CredentialUsername` | `DOMAIN\user` for Admin$/WMI auth. Leave `''` for current user | `''` |

### ndtrack Options

| Variable | Description | Default |
|----------|-------------|---------|
| `$NdtrackRelativePath` | Path to `ndtrack.exe` relative to `\\Beacon\mgsRET$` | `Inventory\ndtrack.exe` |
| `$NdtrackExtraArgs` | Additional `-o` arguments passed to ndtrack | `-o LogModules=default -o IgnoreConnectionWindows=true` |
| `$StageNdtrackLocally` | Copy ndtrack to the target and run locally — use when UNC execution is blocked by AppLocker/WDAC/EDR | `$false` |
| `$SkipNdtrackExecution` | Skip ndtrack entirely (safe/read-only mode) | `$false` |

### Report Output

| Variable | Description | Default |
|----------|-------------|---------|
| `$ReportOutputDir` | Directory where reports are saved automatically | `C:\Diag\ZFP Reports\` |
| `$ReportFormat` | `HTML` or `CSV` | `HTML` |
| `$HtmlReportPath` | Override: specific full file path for the report (single-target only). Overrides `$ReportOutputDir`. | `''` |

Report files are named **`YYYY-MM-DD_<ComputerName>.html`** (or `.csv`).

If the report directory doesn't exist the script will ask permission before creating it. If HTML generation fails for any reason, it automatically falls back to CSV.

### Other

| Variable | Description | Default |
|----------|-------------|---------|
| `$RemoteDiagDir` | Temp directory created on the target for output capture | `C:\Windows\Temp\FlexeraZFPDiag` |

---

## CSV / Multi-Target Mode

To run against a list of machines, switch to CSV mode:

```powershell
$RunMode         = 'Csv'
$TargetCsvPath   = 'C:\Diag\zfp_targets.csv'
$MaxParallelJobs = 3     # 1 = sequential, 2-5 = parallel
```

### CSV Format

Save as UTF-8 with a header row. Column names are case-insensitive.

```csv
ComputerName,BeaconHostname,UploadServer,UploadProtocol,UploadPort,ReportPath
WORKSTATION01,,,,,
WORKSTATION02,BEACON02,BEACON02,http,80,
10.10.5.50,,,,,C:\Diag\server50.html
```

| Column | Required | Description |
|--------|----------|-------------|
| `ComputerName` | **Yes** | Hostname, FQDN, or IP of the target |
| `BeaconHostname` | No | Override beacon server for this row |
| `UploadServer` | No | Override upload server for this row |
| `UploadProtocol` | No | `http` or `https` |
| `UploadPort` | No | Port number |
| `ReportPath` | No | Full path override for this target's report |

Leave any optional cell blank to inherit the value from the config block. All targets share the single credential configured in `$CredentialUsername`.

### Parallel Execution (PS 5.1)

PowerShell 5.1 has no `ForEach-Object -Parallel`. The script uses **`Start-Job`** — each target spawns a separate `powershell.exe` subprocess running this same script file with per-target arguments injected via its internal `param()` block.

The credential is serialised once using **Windows DPAPI** (`ConvertFrom-SecureString` with no key). Spawned jobs run under the same user account and decrypt it transparently — no re-prompting per target.

`$MaxParallelJobs` caps the number of concurrent jobs. Recommended: **3–5**. High values can saturate RPC/SMB on busy networks.

---

## Common Failures & Hints

| Failure | Likely Cause | Fix |
|---------|-------------|-----|
| TCP 135 closed | Firewall blocking RPC | Open TCP 135 from script host to target |
| TCP 445 closed | Firewall blocking SMB | Open TCP 445 from script host to target |
| Admin$ write fails | Insufficient rights or UAC remote filtering | Set `LocalAccountTokenFilterPolicy=1` or use domain admin |
| CIM session fails | WMI service down or DCOM blocked | Start `winmgmt`; check DCOM permissions in Component Services |
| Target DNS fails | Target can't resolve Beacon name | Add DNS record or hosts entry on target |
| UNC read fails | `mgsRET$` share permissions | Grant target computer account read access on `mgsRET$` |
| HTTP upload fails | Firewall from target to Beacon port 80 | Open target → Beacon TCP 80 |
| UNC launch fails, staged passes | AppLocker/WDAC/EDR blocking UNC execution | Whitelist ndtrack UNC path or use `$StageNdtrackLocally = $true` |

---

## Output

### Console
Colour-coded results table printed live as each test runs:

```
[PASS] [DNS                           ] Resolve target name              192.168.1.50
[PASS] [Port                          ] TCP 135 RPC Endpoint Mapper      Open
[FAIL] [SMB                           ] Admin$ read/write                Access is denied
```

### Report File
Saved automatically to `$ReportOutputDir` as a dark-themed HTML table (or CSV fallback). Suitable for sharing with firewall/network teams.

### Pipeline
`Test-FlexeraZFARequirements` returns `$Script:Results` — a list of `[PSCustomObject]` with fields `Category`, `Test`, `Result`, `Detail`, `Hint`. Pipe to `Export-Csv` or process further as needed.

---

## Known Limitations

- **ndtrack upload via `Win32_Process.Create`**: ndtrack may fail to upload when launched by this script even though the real beacon scan succeeds. The Flexera Beacon uses `mgsreservice.exe` (running as SYSTEM on the target) rather than plain `Win32_Process.Create`, which produces a different security/network context. Investigation ongoing — use the tracker.log tail (Section 6) to distinguish a genuine upload failure from a test-context artefact.
- **IPv6 not supported** — targets are expected to be reachable over IPv4.
- **Windows targets only** — ZFP agentless scanning is a Windows-to-Windows mechanism.

---

## Related Scripts

| Repo | Description |
|------|-------------|
| [Flexera_PreReq_Check](https://github.com/ultimateunraid/Flexera_PreReq_Check) | Validates TLS, .NET, and Flexera One regional connectivity on the beacon/server |
| [PreReq_Snow](https://github.com/ultimateunraid/PreReq_Snow) | Validates TLS cipher suites, .NET, and Snow Atlas endpoint connectivity |
