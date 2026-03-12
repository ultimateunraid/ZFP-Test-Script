#Requires -Version 5.1
<#
    INTERNAL USE — do not edit these params. They are populated automatically when
    the script re-invokes itself as a parallel job for CSV multi-target runs.
    To run interactively, edit the USER CONFIGURATION block below and run normally.
#>
param(
    [string]$_CsvTargetComputer  = '',
    [string]$_CsvBeaconHostname  = '',
    [string]$_CsvUploadServer    = '',
    [string]$_CsvUploadProtocol  = '',
    [string]$_CsvUploadPort      = '',
    [string]$_CsvHtmlReportPath  = '',
    [string]$_CsvCredUser        = '',
    [string]$_CsvCredPass        = ''   # DPAPI-encrypted SecureString (ConvertFrom-SecureString)
)
# True when the script is running as a background job spawned by the CSV orchestrator.
$_IsBatchJob = ($PSBoundParameters.ContainsKey('_CsvTargetComputer') -and $_CsvTargetComputer -ne '')

<#
.SYNOPSIS
    Diagnostic script for Flexera Zero Footprint Agent (ZFA) / Zero Footprint Inventory (ZFP)
    Windows prerequisite validation.

.DESCRIPTION
    Validates every layer required for a Flexera Beacon to successfully perform agentless
    (zero-footprint) inventory against a Windows target host. Tests are run from the local
    machine (simulating Beacon-side checks) AND via remote WMI/CIM process creation to
    simulate what the target itself must be able to do.

    Test categories:
        1. Local reachability      - DNS, ICMP, TCP 135 (RPC), TCP 445 (SMB)
        2. Authentication / SMB    - Admin$ R/W, C$ access
        3. Remote execution        - WMI/DCOM (Win32_Process.Create)
        4. Target-side checks      - DNS resolution of Beacon, UNC read of ndtrack.exe,
                                     HTTP reach of UploadLocation
        5. ndtrack execution       - UNC launch (Beacon-style) and optional local staging

    OUTPUT:
        - Console summary table with colour-coded pass/warn/fail
        - Optional HTML report saved to a path of your choice
        - Remediation hint block for any failures

.NOTES
    Author  : Gabe (IT Infrastructure)
    Version : 1.2
    Requires: PowerShell 5.1+, run elevated on the machine performing the scan.
    Target  : Windows hosts (Flexera FNMS 2023 R2 ZFA requirements)

    Reference:
        https://docs.flexera.com/FlexNetManagerSuite2023R2/EN/GatherFNInv/index.html
        #SysRef/FlexNetInventoryAgent/topics/ZFA-SystemReqs.html
#>

#region ── USER CONFIGURATION ────────────────────────────────────────────────────
# Edit the values in this section before running the script.

# Hostname, FQDN, or IP of the Windows machine to scan agentlessly.
$TargetComputer      = 'WORKSTATION01'

# Hostname, FQDN, or IP of the Flexera Beacon server that hosts mgsRET$.
$BeaconHostname      = 'BEACON01'

# Hostname, FQDN, or IP of the server hosting ManageSoftRL.
$UploadServer        = 'BEACON01'

# Protocol for the UploadLocation URL: 'http' or 'https'
$UploadProtocol      = 'http'

# Port for the UploadLocation URL.
# Standard defaults: 80 (http) or 443 (https). Set a custom value if needed.
# If using the default port for the chosen protocol it will be omitted from the URL.
$UploadPort          = 80

# Username for Admin$ / WMI authentication (e.g. 'DOMAIN\username' or 'hostname\localadmin').
# Leave empty ('') to run under the current user context without a password prompt.
$CredentialUsername  = 'DOMAIN\username'

# Path to ndtrack.exe relative to \\BeaconHostname\mgsRET$
$NdtrackRelativePath = 'Inventory\ndtrack.exe'

# Additional arguments passed to ndtrack.exe during the execution test.
# The script always supplies -t Machine and -o UploadLocation automatically.
# Add or remove -o arguments here as needed for your environment.
$NdtrackExtraArgs    = '-o LogModules=default -o IgnoreConnectionWindows=true'

# Set to $true to copy ndtrack.exe locally to the target and run it from there.
# Useful when UNC execution is blocked by AppLocker/WDAC/EDR.
$StageNdtrackLocally = $false

# Set to $true to skip launching ndtrack.exe entirely (safe/read-only mode).
$SkipNdtrackExecution = $false

# ── REPORT OUTPUT ─────────────────────────────────────────────────────────────────
#
# Directory where diagnostic reports are automatically saved after each run.
# Report files are named: YYYY-MM-DD_<ComputerName>.html  (or .csv — see $ReportFormat)
# The directory will be created if it does not exist; the script will ask permission first.
# Set to '' to disable automatic report generation.
$ReportOutputDir = 'C:\Diag\ZFP Reports\'

# Report file format: 'HTML' (default) or 'CSV'.
# If HTML generation fails, the script automatically falls back to CSV.
$ReportFormat = 'HTML'

# Override: set a specific full path for the report file (single-target mode only).
# When set, $ReportOutputDir and auto-naming are ignored for this run.
# Leave empty '' to use the auto-named file in $ReportOutputDir.
$HtmlReportPath = ''

# Temp directory created on the target for capturing command output files.
$RemoteDiagDir       = 'C:\Windows\Temp\FlexeraZFPDiag'

# ── MULTI-TARGET / CSV MODE ───────────────────────────────────────────────────────
#
# Set $RunMode to 'Single' to test one machine (uses $TargetComputer above).
# Set $RunMode to 'Csv'    to load a list of targets from a CSV file.
#
$RunMode = 'Single'

# Path to the CSV file used when $RunMode = 'Csv'.
$TargetCsvPath = 'C:\Diag\zfp_targets.csv'

# Maximum number of targets to test at the same time in Csv mode.
# Uses Start-Job (separate PowerShell processes) for true parallelism in PS 5.1.
# Set to 1 to run targets one at a time (sequential — easier to read console output).
# Recommended range: 1-5. High values can saturate RPC/SMB on busy networks.
$MaxParallelJobs = 3

<#
  ── CSV FILE FORMAT ──────────────────────────────────────────────────────────────
  Save as UTF-8 with headers on the first row.
  Column names are case-insensitive.

  REQUIRED column:
    ComputerName        Hostname, FQDN, or IP of the Windows target to scan.

  OPTIONAL columns (leave the cell blank to inherit the value from the config block):
    BeaconHostname      Override the beacon server for this target.
    UploadServer        Override the upload/ManageSoftRL server for this target.
    UploadProtocol      'http' or 'https'  (default: value of $UploadProtocol above)
    UploadPort          Port number        (default: value of $UploadPort above)
    ReportPath          Full file path override for this target's report.
                        Overrides the auto-named file in $ReportOutputDir for this row.

  Reports are automatically saved to $ReportOutputDir as YYYY-MM-DD_<ComputerName>.html
  (or .csv if $ReportFormat = 'CSV'). All targets share the single credential set in
  $CredentialUsername above (or the current user context if left empty).

  EXAMPLE:
    ComputerName,BeaconHostname,UploadServer,UploadProtocol,UploadPort,ReportPath
    WORKSTATION01,,,,,
    WORKSTATION02,BEACON02,BEACON02,http,80,
    10.10.5.50,,,,,C:\Diag\server50.html
  ─────────────────────────────────────────────────────────────────────────────────
#>

#endregion ── END USER CONFIGURATION ─────────────────────────────────────────────

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region ── DERIVED VARIABLES & STATE ─────────────────────────────────────────────────────

# Apply per-target overrides when running as a CSV batch job subprocess.
# These are set via the param() block at the top; the orchestrator passes them.
if ($_IsBatchJob) {
    if ($_CsvTargetComputer -ne '')  { $TargetComputer   = $_CsvTargetComputer }
    if ($_CsvBeaconHostname -ne '')  { $BeaconHostname   = $_CsvBeaconHostname }
    if ($_CsvUploadServer   -ne '')  { $UploadServer     = $_CsvUploadServer   }
    if ($_CsvUploadProtocol -ne '')  { $UploadProtocol   = $_CsvUploadProtocol }
    if ($_CsvUploadPort     -ne '')  { $UploadPort       = [int]$_CsvUploadPort }
    if ($_CsvHtmlReportPath -ne '')  { $HtmlReportPath   = $_CsvHtmlReportPath }
}

# Build the full UploadLocation URL from the config values above.
$defaultPort = (($UploadProtocol -eq 'https') -and ($UploadPort -eq 443)) -or (($UploadProtocol -eq 'http') -and ($UploadPort -eq 80))
if ($defaultPort) {
    $UploadLocation = "${UploadProtocol}://${UploadServer}/ManageSoftRL"
} else {
    $UploadLocation = "${UploadProtocol}://${UploadServer}:${UploadPort}/ManageSoftRL"
}
# Test endpoint — returns "Test succeeded" on a healthy beacon
$UploadTestURL  = "$UploadLocation/test"

# Build the full ndtrack UNC path.
$NdtrackUNC     = "\\$BeaconHostname\mgsRET`$\$NdtrackRelativePath"

# C$ path used for reading captured output files off the target.
$DiagDirRemoteAdmin = $RemoteDiagDir -replace '^C:\\', "\\$TargetComputer\C`$\"

# Credential resolution — three paths:
#   1. Running as a batch job subprocess: credential was DPAPI-serialised by the orchestrator
#      and passed via $_CsvCredPass. Deserialise it here (DPAPI works within same user context).
#   2. Interactive single/csv mode with a username configured: prompt once.
#   3. No username: run as the current user (no prompt).
if ($_IsBatchJob -and $_CsvCredPass -ne '') {
    try {
        $secPass    = $_CsvCredPass | ConvertTo-SecureString   # DPAPI decrypt (same user session)
        $Credential = [PSCredential]::new($_CsvCredUser, $secPass)
    } catch {
        Write-Warning "Could not deserialise credential in batch job — running as current user. Error: $($_.Exception.Message)"
        $Credential = $null
    }
} elseif ($CredentialUsername -ne '') {
    $Credential = Get-Credential -UserName $CredentialUsername `
                                 -Message "Enter password for $CredentialUsername (used for Admin$ and WMI access to $TargetComputer)"
} else {
    $Credential = $null
}

$Script:Results      = [System.Collections.Generic.List[PSObject]]::new()
$Script:CimSession   = $null   # Reusable CIM session

$PASS  = 'PASS'
$WARN  = 'WARN'
$FAIL  = 'FAIL'
$INFO  = 'INFO'
$SKIP  = 'SKIP'

#endregion

#region ── RESULT HELPERS ────────────────────────────────────────────────────────

function New-TestResult {
    param(
        [string]$Category,
        [string]$Test,
        [string]$Result,   # PASS / FAIL / WARN / INFO / SKIP
        [string]$Detail,
        [string]$Hint = ''
    )
    $obj = [PSCustomObject]@{
        Category = $Category
        Test     = $Test
        Result   = $Result
        Detail   = $Detail
        Hint     = $Hint
    }
    $Script:Results.Add($obj)
    return $obj
}

function Write-TestResult {
    param([PSCustomObject]$r)
    $color = switch ($r.Result) {
        $PASS { 'Green'   }
        $FAIL { 'Red'     }
        $WARN { 'Yellow'  }
        $INFO { 'Cyan'    }
        $SKIP { 'DarkGray'}
        default { 'White' }
    }
    $line = "[{0,-4}] [{1,-30}] {2,-40} {3}" -f $r.Result, $r.Category, $r.Test, $r.Detail
    Write-Host $line -ForegroundColor $color
}

function Add-Result {
    param(
        [string]$Category,
        [string]$Test,
        [string]$Result,
        [string]$Detail,
        [string]$Hint = ''
    )
    $r = New-TestResult @PSBoundParameters
    Write-TestResult $r
    return $r
}

#endregion

#region ── WMI/CIM HELPERS ───────────────────────────────────────────────────────

<#
.DESCRIPTION
    Returns a CIM session to the target using DCOM exclusively.
    Session is cached in $Script:CimSession.
    WinRM/WSMan is intentionally not used — Flexera Beacon uses DCOM (Win32_Process.Create)
    and a WSMan-only success would be a false PASS.
#>
function Get-TargetCimSession {
    if ($Script:CimSession -and $Script:CimSession.TestConnection()) {
        return $Script:CimSession
    }
    $cimOpts = @{ ComputerName = $TargetComputer; ErrorAction = 'Stop' }
    if ($Credential) { $cimOpts['Credential'] = $Credential }

    # DCOM only — matches the transport Flexera Beacon uses for Win32_Process.Create.
    # WinRM/WSMan is intentionally not used or tested.
    $cimOpts['SessionOption'] = New-CimSessionOption -Protocol Dcom
    $Script:CimSession = New-CimSession @cimOpts
    return $Script:CimSession
}

<#
.DESCRIPTION
    Maps the return code from Win32_Process.Create() to a human-readable string.
    Reference: https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/create-method-in-class-win32-process
#>
function Get-WmiCreateReturnText {
    param([int]$Code)
    $map = @{
        0  = 'Success'
        2  = 'Access Denied'
        3  = 'Insufficient Privilege'
        8  = 'Unknown failure'
        9  = 'Path Not Found'
        21 = 'Invalid Parameter'
    }
    if ($map.ContainsKey($Code)) { return $map[$Code] } else { return "Unknown code ($Code)" }
}

<#
.DESCRIPTION
    Runs a command on the target via Win32_Process.Create (the same mechanism the
    Flexera Beacon uses for ZFP remote process creation).

    IMPROVEMENT: Uses CIM (New-CimSession + Invoke-CimMethod) instead of the
    deprecated Get-WmiObject approach. Behaviour is identical; reliability is better.
    Also wraps cmd /c to capture output to files in $RemoteDiagDir.

    Returns a PSCustomObject: { ReturnCode, ReturnText, ProcessId, Error }
#>
function Invoke-RemoteCimProcess {
    param(
        [string]$CommandLine,
        [string]$Description = $CommandLine
    )
    try {
        $session = Get-TargetCimSession
        $result  = Invoke-CimMethod -CimSession $session `
                                    -ClassName  Win32_Process `
                                    -MethodName Create `
                                    -Arguments  @{ CommandLine = $CommandLine }
        return [PSCustomObject]@{
            ReturnCode  = $result.ReturnValue
            ReturnText  = Get-WmiCreateReturnText $result.ReturnValue
            ProcessId   = $result.ProcessId
            Error       = $null
        }
    } catch {
        return [PSCustomObject]@{
            ReturnCode  = -1
            ReturnText  = 'Exception'
            ProcessId   = $null
            Error       = $_.Exception.Message
        }
    }
}

<#
.DESCRIPTION
    Runs a command on the target, writing stdout/stderr/exit code to files in
    $RemoteDiagDir, then waits for the process to exit (with timeout).
    Returns the file stems so callers can read them back via Admin$.

    The wrapper pattern is:
        cmd /c "<command>" > stdout.txt 2> stderr.txt & echo %errorlevel% > exit.txt
#>
function Invoke-RemoteCapturedProcess {
    param(
        [string]$Tag,          # Short identifier used in output filenames
        [string]$InnerCommand, # The actual command to run
        [int]   $TimeoutSec = 120
    )
    $stdoutFile = "$RemoteDiagDir\${Tag}.stdout.txt"
    $stderrFile = "$RemoteDiagDir\${Tag}.stderr.txt"
    $exitFile   = "$RemoteDiagDir\${Tag}.exit.txt"

    # Do NOT wrap $InnerCommand in outer quotes — it carries its own quoting.
    # Use "call echo %errorlevel%" — plain echo expands %errorlevel% at parse time
    # (before InnerCommand runs), so always captures the wrong exit code.
    $wrapped = "C:\Windows\System32\cmd.exe /c $InnerCommand > `"$stdoutFile`" 2> `"$stderrFile`" & call echo %errorlevel% > `"$exitFile`""

    $launchResult = Invoke-RemoteCimProcess -CommandLine $wrapped -Description $Tag
    if ($launchResult.ReturnCode -ne 0) {
        return [PSCustomObject]@{
            Launched    = $false
            TimedOut    = $false
            LaunchError = "$($launchResult.ReturnText) | $($launchResult.Error)"
            StdoutFile  = $stdoutFile
            StderrFile  = $stderrFile
            ExitFile    = $exitFile
            ProcessId   = $null
        }
    }

    # Poll for process exit (avoid indefinite hang).
    # Guard: only poll if ProcessId is valid (> 0); a PID of 0 is the System Idle process.
    $timedOut = $false
    if ($launchResult.ProcessId -gt 0) {
        $deadline = [datetime]::UtcNow.AddSeconds($TimeoutSec)
        do {
            Start-Sleep -Seconds 3
            try {
                $session = Get-TargetCimSession
                $running = Get-CimInstance -CimSession $session -ClassName Win32_Process `
                           -Filter "ProcessId = $($launchResult.ProcessId)" -ErrorAction SilentlyContinue
            } catch { $running = $null }
        } while ($running -and [datetime]::UtcNow -lt $deadline)

        if ($running) { $timedOut = $true }
    }

    return [PSCustomObject]@{
        Launched    = $true
        TimedOut    = $timedOut
        LaunchError = $null
        StdoutFile  = $stdoutFile
        StderrFile  = $stderrFile
        ExitFile    = $exitFile
        ProcessId   = $launchResult.ProcessId
    }
}

#endregion

#region ── SMB HELPERS ───────────────────────────────────────────────────────────

<#
.DESCRIPTION
    Maps \\Target\Admin$ to a temporary PSDrive and runs a scriptblock within that
    context, then removes the drive. Returns whatever the scriptblock returns.
    Caches the drive letter in $Script:AdminDrive for reuse within one session.
#>
function Use-AdminShareDrive {
    param([scriptblock]$Action)
    $driveLetter = 'ZFPDiag'
    $unc         = "\\$TargetComputer\Admin$"

    $mapArgs = @{ Name = $driveLetter; PSProvider = 'FileSystem'; Root = $unc; ErrorAction = 'Stop' }
    if ($Credential) { $mapArgs['Credential'] = $Credential }

    try {
        if (-not (Get-PSDrive -Name $driveLetter -ErrorAction SilentlyContinue)) {
            New-PSDrive @mapArgs | Out-Null
        }
        return (& $Action)
    } finally {
        if (Get-PSDrive -Name $driveLetter -ErrorAction SilentlyContinue) {
            Remove-PSDrive -Name $driveLetter -Force -ErrorAction SilentlyContinue
        }
    }
}

<#
.DESCRIPTION
    Reads a remote file back via C$ (C:\... → \\Target\C$\...).
    Uses C$ rather than Admin$ so $RemoteDiagDir can be outside C:\Windows\.
    Returns the content as a string, or $null on failure.
#>
function Read-RemoteTextViaAdmin {
    param([string]$RemotePath)   # e.g. C:\Windows\Temp\FlexeraZFPDiag\foo.txt
    $relative = $RemotePath -replace '^C:\\', ''
    $unc      = "\\$TargetComputer\C$\$relative"
    try {
        return (Get-Content -LiteralPath $unc -Raw -ErrorAction Stop)
    } catch {
        return $null
    }
}

<#
.DESCRIPTION
    Tails the last N lines of known tracker.log locations on the target via C$.
    Searches common FNMS/FlexNet log paths.
#>
function Get-RemoteTrackerLogTail {
    param([int]$Lines = 50)

    # Static candidate paths (no wildcards)
    $staticCandidates = @(
        "\\$TargetComputer\C$\Windows\Temp\ManageSoft\tracker.log",
        "\\$TargetComputer\C$\ProgramData\Flexera Software\Compliance\Logging\tracker.log",
        "\\$TargetComputer\C$\Program Files (x86)\ManageSoft\tracker.log"
    )
    foreach ($path in $staticCandidates) {
        try {
            $content = Get-Content -LiteralPath $path -Tail $Lines -ErrorAction Stop
            return [PSCustomObject]@{ Path = $path; Lines = $content }
        } catch { }
    }

    # Wildcard search: C:\Users\<any user>\AppData\Local\Temp\<any numeric subdir>\ManageSoft\tracker.log
    # ndtrack runs as the invoking user so the log lands under their profile temp folder,
    # which Windows may place in a numbered subfolder (1, 2, 3...) under %TEMP%.
    $usersRoot = "\\$TargetComputer\C$\Users"
    try {
        $found = Get-ChildItem -Path $usersRoot -Directory -ErrorAction Stop |
            ForEach-Object {
                $userTemp = Join-Path $_.FullName 'AppData\Local\Temp'
                # Check direct ManageSoft folder and one level of numeric subfolders
                $directLog = Join-Path $userTemp 'ManageSoft\tracker.log'
                if (Test-Path -LiteralPath $directLog -ErrorAction SilentlyContinue) {
                    return $directLog
                }
                # Numbered subdirs (e.g. Temp\1\, Temp\2\, Temp\3\)
                if (Test-Path -LiteralPath $userTemp -ErrorAction SilentlyContinue) {
                    Get-ChildItem -Path $userTemp -Directory -ErrorAction SilentlyContinue |
                        Where-Object { $_.Name -match '^\d+$' } |
                        ForEach-Object {
                            $subLog = Join-Path $_.FullName 'ManageSoft\tracker.log'
                            if (Test-Path -LiteralPath $subLog -ErrorAction SilentlyContinue) {
                                return $subLog
                            }
                        }
                }
            } | Select-Object -First 1

        if ($found) {
            $content = Get-Content -LiteralPath $found -Tail $Lines -ErrorAction Stop
            return [PSCustomObject]@{ Path = $found; Lines = $content }
        }
    } catch { }

    return $null
}

#endregion

#region ── SECTION 1: LOCAL REACHABILITY ─────────────────────────────────────────

function Test-DNSLocal {
    Write-Host "`n── [1] LOCAL REACHABILITY ──────────────────────────────────────" -ForegroundColor DarkCyan

    # Test resolution of TargetComputer — skip if it is already an IP address
    $ipPattern = '^(\d{1,3}\.){3}\d{1,3}$'
    if ($TargetComputer -match $ipPattern) {
        Add-Result -Category 'DNS' -Test 'Resolve target name' -Result $INFO `
            -Detail "$TargetComputer is an IP address — DNS resolution skipped"
    } else {
        try {
            $resolved = [System.Net.Dns]::GetHostAddresses($TargetComputer)
            $ips      = ($resolved | Where-Object { $_.AddressFamily -eq 'InterNetwork' } |
                         ForEach-Object { $_.IPAddressToString }) -join ', '
            Add-Result -Category 'DNS' -Test 'Resolve target name' -Result $PASS -Detail $ips
        } catch {
            Add-Result -Category 'DNS' -Test 'Resolve target name' -Result $FAIL `
                -Detail $_.Exception.Message `
                -Hint 'Fix DNS/hosts file before any other test can succeed.'
        }
    }

    # Also test local resolution of BeaconHostname — required for UNC path construction
    if ($BeaconHostname -match $ipPattern) {
        Add-Result -Category 'DNS' -Test 'Resolve BeaconHostname (local)' -Result $INFO `
            -Detail "$BeaconHostname is an IP address — DNS resolution skipped"
    } else {
        try {
            $resolved = [System.Net.Dns]::GetHostAddresses($BeaconHostname)
            $ips      = ($resolved | Where-Object { $_.AddressFamily -eq 'InterNetwork' } |
                         ForEach-Object { $_.IPAddressToString }) -join ', '
            Add-Result -Category 'DNS' -Test 'Resolve BeaconHostname (local)' -Result $PASS -Detail $ips
        } catch {
            Add-Result -Category 'DNS' -Test 'Resolve BeaconHostname (local)' -Result $FAIL `
                -Detail $_.Exception.Message `
                -Hint "Local machine cannot resolve '$BeaconHostname'. The UNC path to mgsRET$ will fail."
        }
    }
}

function Test-PingInfo {
    # Informational only — ICMP is NOT required for ZFP but helps confirm basic reachability.
    try {
        $ping = Test-Connection -ComputerName $TargetComputer -Count 2 -ErrorAction Stop
        $avg  = [math]::Round(($ping | Measure-Object -Property ResponseTime -Average).Average, 0)
        Add-Result -Category 'ICMP' -Test 'Ping (informational)' -Result $INFO `
            -Detail "Avg RTT ${avg}ms — ICMP is NOT required by ZFP"
    } catch {
        Add-Result -Category 'ICMP' -Test 'Ping (informational)' -Result $INFO `
            -Detail 'No ICMP response — this is acceptable if firewall blocks ping'
    }
}

<#
.DESCRIPTION
    IMPROVEMENT: Uses Test-NetConnection (built-in since PS 4.0) instead of raw
    .NET socket code. Produces richer output (NameResolutionResults, TcpTestSucceeded)
    and avoids unhandled socket exceptions on timeout.
#>
function Test-TCPPorts {
    $ports = @(
        @{ Port = 135;  Name = 'RPC Endpoint Mapper'; Required = $true;
           Hint = 'TCP 135 must be open for WMI/DCOM remote process creation (Win32_Process.Create).' },
        @{ Port = 445;  Name = 'SMB (Admin$ access)';  Required = $true;
           Hint = 'TCP 445 must be open for Admin$ share access and log retrieval.' }
    )

    foreach ($p in $ports) {
        try {
            $tnc = Test-NetConnection -ComputerName $TargetComputer -Port $p.Port `
                                      -WarningAction SilentlyContinue -ErrorAction Stop
            $ok  = $tnc.TcpTestSucceeded
            $resultStr  = if ($ok) { $PASS } else { $FAIL }
            $detailStr  = if ($ok) { 'Open' } else { 'Closed / Filtered' }
            $hintStr    = if ($ok) { '' } else { $p.Hint }
            Add-Result -Category 'Port' -Test "TCP $($p.Port) $($p.Name)" `
                -Result $resultStr `
                -Detail $detailStr `
                -Hint   $hintStr
        } catch {
            Add-Result -Category 'Port' -Test "TCP $($p.Port) $($p.Name)" `
                -Result $FAIL -Detail $_.Exception.Message -Hint $p.Hint
        }
    }
}

#endregion

#region ── SECTION 2: SMB / ADMIN$ ───────────────────────────────────────────────

function Test-AdminShareRW {
    Write-Host "`n── [2] SMB / ADMIN$ ACCESS ─────────────────────────────────────" -ForegroundColor DarkCyan
    $testFile = "\\$TargetComputer\Admin$\Temp\ZFPDiagTest_$([guid]::NewGuid().ToString('N').Substring(0,8)).tmp"
    try {
        Use-AdminShareDrive {
            # Write test
            [IO.File]::WriteAllText($testFile, 'ZFP_DIAG_OK')
            # Read back
            $content = [IO.File]::ReadAllText($testFile)
            # Delete
            Remove-Item -LiteralPath $testFile -Force -ErrorAction SilentlyContinue
            return $content
        } | Out-Null

        Add-Result -Category 'SMB' -Test 'Admin$ read/write' -Result $PASS `
            -Detail "\\$TargetComputer\Admin$ writable"
    } catch {
        Add-Result -Category 'SMB' -Test 'Admin$ read/write' -Result $FAIL `
            -Detail $_.Exception.Message `
            -Hint 'Verify credentials have local admin rights; check UAC remote restrictions (LocalAccountTokenFilterPolicy).'
    }
}

function Test-CShareRead {
    # C$ read confirms broad admin share access (used for log tailing)
    $path   = "\\$TargetComputer\C$\Windows\System32\cmd.exe"
    $stream = $null
    try {
        $stream = [IO.File]::OpenRead($path)
        Add-Result -Category 'SMB' -Test 'C$ share readable' -Result $PASS -Detail $path
    } catch {
        Add-Result -Category 'SMB' -Test 'C$ share readable' -Result $WARN `
            -Detail $_.Exception.Message `
            -Hint 'C$ access is needed for log tailing. Not strictly required for ZFP itself.'
    } finally {
        if ($stream) { $stream.Dispose() }
    }
}

#endregion

#region ── SECTION 3: REMOTE EXECUTION (WMI/CIM) ────────────────────────────────

function Test-RemoteExecution {
    Write-Host "`n── [3] REMOTE EXECUTION (WMI/DCOM) ────────────────────────────" -ForegroundColor DarkCyan

    # 3a. CIM Session establishment
    try {
        $null = Get-TargetCimSession
        $proto = $Script:CimSession.Protocol
        Add-Result -Category 'WMI/CIM' -Test 'CIM session established' -Result $PASS `
            -Detail "Connected via $proto"
    } catch {
        Add-Result -Category 'WMI/CIM' -Test 'CIM session established' -Result $FAIL `
            -Detail $_.Exception.Message `
            -Hint 'Ensure TCP 135 (RPC Endpoint Mapper) and dynamic RPC ports (typically 49152-65535) are open. Verify DCOM/WMI service is running and credentials are valid.'
        return  # Nothing further will work
    }

    # 3b. Smoke test: create diag directory on target, then verify it exists via Admin$
    # IMPORTANT: Invoke-RemoteCimProcess returns as soon as the process launches — it does
    # NOT wait for the process to finish. We must poll for the directory's existence via
    # Admin$ before any subsequent tests try to write output files into it.
    $mkdirCmd = "C:\Windows\System32\cmd.exe /c mkdir `"$RemoteDiagDir`" 2>nul"
    $r        = Invoke-RemoteCimProcess -CommandLine $mkdirCmd -Description 'mkdir diag dir'
    if ($r.ReturnCode -ne 0) {
        Add-Result -Category 'WMI/CIM' -Test 'Remote process creation (smoke test)' -Result $FAIL `
            -Detail "$($r.ReturnText) | $($r.Error)" `
            -Hint   'Check DCOM Launch/Access permissions in Component Services. Verify WMI service on target.'
        return
    }

    # Poll via C$ until the directory appears (up to 15 seconds)
    $diagDirAdminPath = $RemoteDiagDir -replace '^C:\\', "\\$TargetComputer\C`$\"
    $dirReady  = $false
    $dirDeadline = [datetime]::UtcNow.AddSeconds(15)
    do {
        Start-Sleep -Seconds 2
        if (Test-Path -LiteralPath $diagDirAdminPath -ErrorAction SilentlyContinue) {
            $dirReady = $true
        }
    } while (-not $dirReady -and [datetime]::UtcNow -lt $dirDeadline)

    if ($dirReady) {
        Add-Result -Category 'WMI/CIM' -Test 'Remote process creation (smoke test)' -Result $PASS `
            -Detail "Win32_Process.Create returned 0 — diag dir confirmed at $RemoteDiagDir"
    } else {
        Add-Result -Category 'WMI/CIM' -Test 'Remote process creation (smoke test)' -Result $WARN `
            -Detail "Process launched but diag dir not visible via C$ after 15s — output capture may fail" `
            -Hint   "Check C$ access. Dir may still exist on target but credentials may lack C$ read access."
    }

}

#endregion

#region ── SECTION 4: TARGET-SIDE CHECKS ────────────────────────────────────────

<#
.DESCRIPTION
    These tests run commands ON the target (via Win32_Process.Create) and read back
    their output via Admin$ — this is the most valuable diagnostic category because
    it mirrors exactly what the target must be able to do during a real ZFP scan.
#>

function Test-TargetSideDNS {
    Write-Host "`n── [4] TARGET-SIDE CHECKS ──────────────────────────────────────" -ForegroundColor DarkCyan
    $proc = Invoke-RemoteCapturedProcess -Tag 'dns_beacon' `
                -InnerCommand "C:\Windows\System32\nslookup.exe $BeaconHostname" -TimeoutSec 30
    if (-not $proc.Launched) {
        Add-Result -Category 'Target→DNS' -Test "Resolve BeaconHost ($BeaconHostname)" `
            -Result $FAIL -Detail "Launch failed: $($proc.LaunchError)" `
            -Hint 'Remote process creation failed before DNS could be tested.'
        return
    }
    if ($proc.TimedOut) {
        Add-Result -Category 'Target→DNS' -Test "Resolve BeaconHost ($BeaconHostname)" `
            -Result $WARN -Detail 'nslookup launched but did not exit within 30s (timed out)' `
            -Hint 'DNS query may be hanging. Check DNS server reachability from target.'
        return
    }
    $out  = Read-RemoteTextViaAdmin -RemotePath $proc.StdoutFile
    $err  = Read-RemoteTextViaAdmin -RemotePath $proc.StderrFile
    $exit = $null; $rawExit = Read-RemoteTextViaAdmin -RemotePath $proc.ExitFile; if ($rawExit) { $exit = $rawExit.Trim() }

    # nslookup exits 0 and prints "Address:" when resolution succeeds.
    # Require both the exit code and the address line to avoid false PASS from the
    # default-server line that nslookup always prints before querying.
    if ($exit -eq '0' -and $out -match 'Address:') {
        Add-Result -Category 'Target→DNS' -Test "Resolve BeaconHost ($BeaconHostname)" `
            -Result $PASS -Detail (($out -split "`n" | Select-Object -Last 3) -join ' | ')
    } else {
        Add-Result -Category 'Target→DNS' -Test "Resolve BeaconHost ($BeaconHostname)" `
            -Result $FAIL `
            -Detail "Exit $exit | stdout: $(if ($out) { $out.Trim() }) | stderr: $(if ($err) { $err.Trim() })" `
            -Hint "Target cannot resolve '$BeaconHostname'. Check DNS on the target or add a hosts entry."
    }
}

function Test-TargetUNCRead {
    # Can the target see \\Beacon\mgsRET$\Inventory\ndtrack.exe?
    $proc = Invoke-RemoteCapturedProcess -Tag 'unc_read' `
                -InnerCommand "dir `"$NdtrackUNC`"" -TimeoutSec 45
    if (-not $proc.Launched) {
        Add-Result -Category 'Target→UNC' -Test 'Read ndtrack.exe from Beacon share' `
            -Result $FAIL -Detail "Launch failed: $($proc.LaunchError)" `
            -Hint 'Remote process creation failed before UNC test could run.'
        return
    }
    if ($proc.TimedOut) {
        Add-Result -Category 'Target→UNC' -Test 'Read ndtrack.exe from Beacon share' `
            -Result $WARN -Detail 'dir command launched but did not exit within 45s (timed out)' `
            -Hint 'UNC access may be hanging. Check SMB connectivity from target to Beacon.'
        return
    }
    $out  = Read-RemoteTextViaAdmin -RemotePath $proc.StdoutFile
    $exit = $null; $raw = Read-RemoteTextViaAdmin -RemotePath $proc.ExitFile; if ($raw) { $exit = $raw.Trim() }

    if ($exit -eq '0') {
        Add-Result -Category 'Target→UNC' -Test 'Read ndtrack.exe from Beacon share' `
            -Result $PASS -Detail "Exit 0 | $(($out -split "`n" | Select-Object -Last 2) -join ' ')"
    } else {
        $outTrimmed = if ($out) { $out.Trim() } else { '' }
        Add-Result -Category 'Target→UNC' -Test 'Read ndtrack.exe from Beacon share' `
            -Result $FAIL `
            -Detail "Exit $exit | $outTrimmed" `
            -Hint "Check mgsRET$ share permissions on Beacon. Ensure target computer account has read access."
    }
}

function Test-TargetHTTPUploadLocation {
    # Hits the /test endpoint which returns "Test succeeded" on a healthy beacon.
    # Writes a .ps1 script to the target via Admin$, then runs it via
    # Invoke-RemoteCapturedProcess so output capture and process wait are
    # handled consistently with all other target-side tests.

    $scriptPath      = "$RemoteDiagDir\http_test.ps1"
    $scriptAdminPath = $scriptPath -replace '^C:\\', "\\$TargetComputer\C`$\"

    # Prefix output lines with STATUS:/ERROR: so we can parse them without
    # relying on fragile line-number or regex matching of raw HTTP status codes.
    $psScript = @'
try {
    $r = Invoke-WebRequest -Uri 'UPLOADTESTURL_PLACEHOLDER' -UseBasicParsing -TimeoutSec 15 -ErrorAction Stop
    Write-Output ("STATUS:" + $r.StatusCode)
    Write-Output $r.Content
    exit 0
} catch {
    Write-Output ("ERROR:" + $_.Exception.Message)
    exit 1
}
'@
    $psScript = $psScript -replace 'UPLOADTESTURL_PLACEHOLDER', $UploadTestURL

    try {
        [IO.File]::WriteAllText($scriptAdminPath, $psScript)
    } catch {
        Add-Result -Category 'Target→HTTP' -Test 'Reach UploadLocation (/test)' `
            -Result $FAIL -Detail "Could not stage test script via Admin`$: $($_.Exception.Message)" `
            -Hint 'Confirm Admin$ write access is working (Section 2 should show PASS).'
        return
    }

    $psExe = "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
    $proc  = Invoke-RemoteCapturedProcess -Tag 'http_upload' `
                 -InnerCommand "$psExe -NonInteractive -ExecutionPolicy Bypass -File `"$scriptPath`"" `
                 -TimeoutSec 45

    if (-not $proc.Launched) {
        Add-Result -Category 'Target→HTTP' -Test 'Reach UploadLocation (/test)' `
            -Result $FAIL -Detail "Launch failed: $($proc.LaunchError)" `
            -Hint 'Remote process creation failed before HTTP test could run.'
        return
    }
    if ($proc.TimedOut) {
        Add-Result -Category 'Target→HTTP' -Test 'Reach UploadLocation (/test)' `
            -Result $WARN -Detail 'PowerShell HTTP test launched but did not exit within 45s (timed out)' `
            -Hint "HTTP connection to $UploadTestURL may be hanging. Check firewall rules between target and Beacon."
        return
    }

    $out  = Read-RemoteTextViaAdmin -RemotePath $proc.StdoutFile
    $err  = Read-RemoteTextViaAdmin -RemotePath $proc.StderrFile
    $exit = $null
    $rawExit = Read-RemoteTextViaAdmin -RemotePath $proc.ExitFile
    if ($rawExit) { $exit = $rawExit.Trim() }

    $testSucceeded = $out -match 'Test succeeded'
    $statusLine    = ($out -split "`r?`n" | Where-Object { $_ -match '^STATUS:' } | Select-Object -First 1)
    $statusCode    = if ($statusLine) { ($statusLine -replace '^STATUS:', '').Trim() } else { '' }
    $errorLine     = ($out -split "`r?`n" | Where-Object { $_ -match '^ERROR:'  } | Select-Object -First 1)

    if ($exit -eq '0' -and $testSucceeded) {
        Add-Result -Category 'Target→HTTP' -Test 'Reach UploadLocation (/test)' `
            -Result $PASS `
            -Detail "HTTP $statusCode — 'Test succeeded' confirmed at $UploadTestURL"
    } elseif ($exit -eq '0') {
        $outSnip = if ($out) { $out.Trim().Substring(0, [Math]::Min(120, $out.Trim().Length)) } else { '' }
        Add-Result -Category 'Target→HTTP' -Test 'Reach UploadLocation (/test)' `
            -Result $WARN `
            -Detail "HTTP $statusCode — reachable but 'Test succeeded' not in response: $outSnip" `
            -Hint 'Beacon responded but content unexpected. Verify ManageSoftRL is healthy.'
    } else {
        $errDetail = if ($errorLine) { ($errorLine -replace '^ERROR:', '').Trim() } `
                     elseif ($err)   { $err.Trim() } `
                     else            { '(no output captured)' }
        Add-Result -Category 'Target→HTTP' -Test 'Reach UploadLocation (/test)' `
            -Result $FAIL `
            -Detail "Exit $exit | $errDetail" `
            -Hint "Target cannot reach $UploadTestURL. Check firewall rules and that the Beacon HTTP service is running."
    }
}

#endregion

#region ── SECTION 5: NDTRACK EXECUTION ─────────────────────────────────────────

<#
.DESCRIPTION
    Runs ndtrack.exe from the UNC path as the Beacon would during a real ZFP scan.
    IMPROVEMENT: Uses the captured-process helper so stdout/stderr/exit are always
    retrievable via Admin$ regardless of whether UNC execution itself worked.
#>
function Invoke-NdtrackUNC {
    Write-Host "`n── [5] NDTRACK EXECUTION ───────────────────────────────────────" -ForegroundColor DarkCyan

    if ($SkipNdtrackExecution) {
        Add-Result -Category 'ndtrack' -Test 'UNC launch (Beacon-style)' -Result $SKIP `
            -Detail '-SkipNdtrackExecution was set'
        return
    }

    # Launch ndtrack with the correct -t Machine -o argument syntax.
    # NdtrackUNC is intentionally NOT quoted — UNC paths have no spaces so quotes are
    # unnecessary, and cmd /c mangles the command when it starts with a quoted token
    # AND contains additional quoted pairs (like UploadLocation="...").
    $ndCmd = "$NdtrackUNC -t Machine -o UploadLocation=`"$UploadLocation`" $NdtrackExtraArgs"

    # Timeout set to 300s (5 min). Cloud provider metadata probes at 169.254.169.254
    # each timeout at ~21s; 4+ providers = 84s of unavoidable waits before upload starts.
    $proc = Invoke-RemoteCapturedProcess -Tag 'ndtrack_unc' -InnerCommand $ndCmd -TimeoutSec 300

    if (-not $proc.Launched) {
        Add-Result -Category 'ndtrack' -Test 'UNC launch (Beacon-style)' `
            -Result $FAIL -Detail "Launch failed: $($proc.LaunchError)" `
            -Hint 'Win32_Process.Create could not launch UNC exe. AppLocker/WDAC/EDR may be blocking UNC execution.'
        return
    }

    if ($proc.TimedOut) {
        Add-Result -Category 'ndtrack' -Test 'UNC launch (Beacon-style)' -Result $WARN `
            -Detail 'Process launched but did not exit within 300s (timed out)' `
            -Hint 'ndtrack is still running or hung. Check tracker.log for progress.'
        return
    }

    $stdout = Read-RemoteTextViaAdmin -RemotePath $proc.StdoutFile
    $stderr = Read-RemoteTextViaAdmin -RemotePath $proc.StderrFile
    $exit   = $null; $rawExit1 = Read-RemoteTextViaAdmin -RemotePath $proc.ExitFile; if ($rawExit1) { $exit = $rawExit1.Trim() }

    $stdoutTrimmed = if ($stdout) { $t = $stdout.Trim(); $t.Substring(0, [Math]::Min(200, $t.Length)) } else { '' }
    $detail = "Exit $exit | stdout: $stdoutTrimmed"

    if ($exit -eq '0') {
        Add-Result -Category 'ndtrack' -Test 'UNC launch (Beacon-style)' -Result $PASS -Detail $detail
    } elseif ($null -eq $exit) {
        Add-Result -Category 'ndtrack' -Test 'UNC launch (Beacon-style)' -Result $WARN `
            -Detail 'Process launched but exit code not captured' `
            -Hint 'ndtrack output files may not be readable. Check Admin$/C$ access.'
    } else {
        Add-Result -Category 'ndtrack' -Test 'UNC launch (Beacon-style)' `
            -Result $FAIL -Detail $detail `
            -Hint 'Non-zero exit from ndtrack. Review captured stdout/stderr and tracker.log.'
    }

    # Print captured output
    Write-Host "`n  ndtrack stdout:" -ForegroundColor DarkGray
    $stdoutDisplay = if ($stdout) { $stdout } else { '(empty)' }
    Write-Host $stdoutDisplay -ForegroundColor DarkGray
    if ($stderr) {
        Write-Host "`n  ndtrack stderr:" -ForegroundColor Yellow
        Write-Host $stderr -ForegroundColor Yellow
    }

    # Show the last 20 lines of tracker.log immediately after ndtrack finishes
    # so the result is visible without waiting for Section 6.
    Write-Host "`n  tracker.log (last 20 lines):" -ForegroundColor DarkGray
    $inlineTail = Get-RemoteTrackerLogTail -Lines 20
    if ($inlineTail) {
        Write-Host "  Source: $($inlineTail.Path)" -ForegroundColor DarkGray
        $inlineTail.Lines | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }
    } else {
        Write-Host "  (tracker.log not found — ndtrack may not have written one yet)" -ForegroundColor DarkGray
    }
}

function Invoke-NdtrackLocalStaged {
    if ($SkipNdtrackExecution) { return }
    if (-not $StageNdtrackLocally) { return }

    Write-Host "`n── [5b] NDTRACK STAGED LOCAL RUN ───────────────────────────────" -ForegroundColor DarkCyan

    # Stage: copy ndtrack.exe from Beacon share to target via Admin$
    $localExe = "$RemoteDiagDir\ndtrack_staged.exe"
    $adminDest = $localExe -replace '^C:\\', "\\$TargetComputer\C`$\"

    try {
        Use-AdminShareDrive {
            Copy-Item -LiteralPath $NdtrackUNC -Destination $adminDest -Force -ErrorAction Stop
        }
        Add-Result -Category 'ndtrack' -Test 'Stage ndtrack.exe locally' -Result $PASS `
            -Detail "Copied to $localExe on target"
    } catch {
        Add-Result -Category 'ndtrack' -Test 'Stage ndtrack.exe locally' -Result $FAIL `
            -Detail $_.Exception.Message `
            -Hint 'Could not copy ndtrack.exe — check Beacon share read access and Admin$ write access.'
        return
    }

    # Run from local path
    $ndArgs = "-t Machine -o UploadLocation=`"$UploadLocation`" $NdtrackExtraArgs"
    $proc   = Invoke-RemoteCapturedProcess -Tag 'ndtrack_local' `
                  -InnerCommand "`"$localExe`" $ndArgs" -TimeoutSec 300

    if (-not $proc.Launched) {
        Add-Result -Category 'ndtrack' -Test 'Staged local run' `
            -Result $FAIL -Detail "Launch failed: $($proc.LaunchError)" `
            -Hint 'Win32_Process.Create could not launch staged exe. Check DCOM permissions.'
        return
    }
    if ($proc.TimedOut) {
        Add-Result -Category 'ndtrack' -Test 'Staged local run' -Result $WARN `
            -Detail 'ndtrack launched but did not exit within 300s (timed out)' `
            -Hint 'ndtrack is still running or hung. Check tracker.log for progress.'
        return
    }

    $stdout = Read-RemoteTextViaAdmin -RemotePath $proc.StdoutFile
    $stderr = Read-RemoteTextViaAdmin -RemotePath $proc.StderrFile
    $exit   = $null; $rawExit2 = Read-RemoteTextViaAdmin -RemotePath $proc.ExitFile; if ($rawExit2) { $exit = $rawExit2.Trim() }

    if ($exit -eq '0') {
        Add-Result -Category 'ndtrack' -Test 'Staged local run' -Result $PASS `
            -Detail "Exit 0 — local execution works. If UNC run failed, UNC execution is blocked (AppLocker/WDAC/EDR)."
    } else {
        $stderrTrimmed = if ($stderr) { $stderr.Trim() } else { '' }
        Add-Result -Category 'ndtrack' -Test 'Staged local run' -Result $FAIL `
            -Detail "Exit $exit | $stderrTrimmed" `
            -Hint 'Even local execution failed. Likely an ndtrack argument, licence, or UploadLocation issue.'
    }

    # Cleanup
    $cleanCmd = "cmd /c del /f /q `"$localExe`""
    Invoke-RemoteCimProcess -CommandLine $cleanCmd | Out-Null
    Add-Result -Category 'ndtrack' -Test 'Cleanup staged exe' -Result $INFO `
        -Detail "Issued delete of $localExe"
}

#endregion

#region ── SECTION 6: TRACKER.LOG TAIL ──────────────────────────────────────────

function Show-TrackerLogTail {
    Write-Host "`n── [6] TRACKER.LOG (last 20 lines) ─────────────────────────────" -ForegroundColor DarkCyan
    $tail = Get-RemoteTrackerLogTail -Lines 20
    if ($tail) {
        Write-Host "  Source: $($tail.Path)" -ForegroundColor DarkGray
        $tail.Lines | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }
        Add-Result -Category 'Logs' -Test 'tracker.log accessible' -Result $INFO `
            -Detail "Found at $($tail.Path)"
    } else {
        Add-Result -Category 'Logs' -Test 'tracker.log accessible' -Result $INFO `
            -Detail 'No tracker.log found in standard locations — may not exist yet on this target.'
    }
}

#endregion

#region ── SUMMARY & REMEDIATION ─────────────────────────────────────────────────

function Get-RemediationHints {
    Write-Host "`n── REMEDIATION HINTS ────────────────────────────────────────────" -ForegroundColor Magenta
    $failures = $Script:Results | Where-Object { $_.Result -in @($FAIL, $WARN) -and $_.Hint }
    if (-not $failures) {
        Write-Host "  No failures with hints — all critical tests passed." -ForegroundColor Green
        return
    }
    foreach ($f in $failures) {
        Write-Host "`n  [$($f.Result)] $($f.Category) — $($f.Test)" -ForegroundColor Yellow
        Write-Host "        $($f.Hint)" -ForegroundColor White
    }
}

function Write-SummaryTable {
    Write-Host "`n══════════════════════════════════════════════════════════════════" -ForegroundColor DarkCyan
    Write-Host "  SUMMARY: Flexera ZFA Requirements — $TargetComputer" -ForegroundColor Cyan
    Write-Host "══════════════════════════════════════════════════════════════════" -ForegroundColor DarkCyan

    $passCount = @($Script:Results | Where-Object Result -eq $PASS).Count
    $failCount = @($Script:Results | Where-Object Result -eq $FAIL).Count
    $warnCount = @($Script:Results | Where-Object Result -eq $WARN).Count
    $infoCount = @($Script:Results | Where-Object Result -in @($INFO, $SKIP)).Count

    $summaryColor = if ($failCount -gt 0) { 'Red' } elseif ($warnCount -gt 0) { 'Yellow' } else { 'Green' }
    Write-Host ("  PASS:{0,3}   FAIL:{1,3}   WARN:{2,3}   INFO/SKIP:{3,3}" -f $passCount, $failCount, $warnCount, $infoCount) `
        -ForegroundColor $summaryColor

    Write-Host ""
    $Script:Results | ForEach-Object { Write-TestResult $_ }
}

#endregion

#region ── REPORT OUTPUT ─────────────────────────────────────────────────────────

<#
.DESCRIPTION
    Resolves the final output path for the diagnostic report.
    Priority:
      1. $HtmlReportPath if explicitly set (single-target override)
      2. Auto-generated YYYY-MM-DD_<ComputerName>.<ext> in $ReportOutputDir
      3. $null if $ReportOutputDir is empty (no report)
    When the target directory does not exist, prompts the user for permission before
    creating it (suppressed in batch job mode — permission was granted interactively).
#>
function Resolve-ReportPath {
    # Explicit override always wins
    if ($HtmlReportPath) { return $HtmlReportPath }

    # No directory configured — no report
    if (-not $ReportOutputDir) { return $null }

    # Create the directory if missing
    if (-not (Test-Path -LiteralPath $ReportOutputDir -ErrorAction SilentlyContinue)) {
        if (-not $_IsBatchJob) {
            Write-Host ""
            $answer = Read-Host "  Report directory '$ReportOutputDir' does not exist. Create it? [Y/N]"
            if ($answer -notmatch '^[Yy]') {
                Write-Host "  Skipping report — directory not created." -ForegroundColor Yellow
                return $null
            }
        }
        try {
            New-Item -Path $ReportOutputDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
            Write-Host "  Created report directory: $ReportOutputDir" -ForegroundColor Cyan
        } catch {
            Write-Warning "Could not create report directory '$ReportOutputDir': $($_.Exception.Message)"
            return $null
        }
    }

    $ext      = if ($ReportFormat -eq 'CSV') { 'csv' } else { 'html' }
    $date     = Get-Date -Format 'yyyy-MM-dd'
    $safeName = $TargetComputer -replace '[\\/:*?"<>|]', '_'
    return Join-Path $ReportOutputDir "${date}_${safeName}.${ext}"
}

<#
.DESCRIPTION
    Exports $Script:Results to a CSV file.
    Used as the primary output when $ReportFormat = 'CSV', and as a fallback
    when HTML generation fails.
#>
function Export-CsvReport {
    param([string]$Path)
    try {
        $Script:Results | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        Write-Host "`n  CSV report saved: $Path" -ForegroundColor Cyan
    } catch {
        Write-Warning "Could not write CSV report to '$Path' — $($_.Exception.Message)"
    }
}

<#
.DESCRIPTION
    Exports $Script:Results as a dark-themed HTML file suitable for sharing with
    firewall / network teams. Throws on write failure so the caller can fall back
    to CSV automatically.
#>
function Export-HtmlReport {
    param([string]$Path)

    $rowColor = @{ PASS='#1a4a1a'; FAIL='#4a1a1a'; WARN='#4a3a00'; INFO='#1a2a4a'; SKIP='#2a2a2a' }
    $textColor= @{ PASS='#7fff7f'; FAIL='#ff7f7f'; WARN='#ffd966'; INFO='#7fbfff'; SKIP='#888888' }

    $rows = $Script:Results | ForEach-Object {
        $bg  = if ($rowColor.ContainsKey($_.Result))  { $rowColor[$_.Result]  } else { '#222' }
        $fg  = if ($textColor.ContainsKey($_.Result)) { $textColor[$_.Result] } else { '#fff' }
        "<tr style='background:$bg'>
            <td style='color:$fg;font-weight:bold'>$($_.Result)</td>
            <td>$($_.Category)</td>
            <td>$($_.Test)</td>
            <td>$($_.Detail)</td>
            <td style='color:#aaa;font-size:0.85em'>$($_.Hint)</td>
         </tr>"
    }

    $html = @"
<!DOCTYPE html><html lang='en'>
<head><meta charset='UTF-8'>
<title>Flexera ZFA Diag — $TargetComputer</title>
<style>
  body{background:#111;color:#ccc;font-family:Consolas,monospace;margin:2em}
  h1{color:#7fbfff} h2{color:#aaa;font-size:1em;font-weight:normal}
  table{border-collapse:collapse;width:100%}
  th{background:#1e3a5f;color:#7fbfff;padding:6px 10px;text-align:left}
  td{padding:5px 10px;border-bottom:1px solid #222;vertical-align:top}
  .meta{color:#666;font-size:0.85em;margin-bottom:1.5em}
</style></head>
<body>
<h1>Flexera Zero Footprint Agent — Diagnostic Report</h1>
<h2>Target: $TargetComputer &nbsp;|&nbsp; Beacon: $BeaconHostname &nbsp;|&nbsp; Run: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</h2>
<p class='meta'>UploadLocation: $UploadLocation</p>
<table>
<thead><tr><th>Result</th><th>Category</th><th>Test</th><th>Detail</th><th>Hint</th></tr></thead>
<tbody>
$($rows -join "`n")
</tbody></table>
</body></html>
"@
    # Let exceptions propagate — caller catches and falls back to CSV.
    [IO.File]::WriteAllText($Path, $html)
    Write-Host "`n  HTML report saved: $Path" -ForegroundColor Cyan
}

#endregion

#region ── CLEANUP ───────────────────────────────────────────────────────────────

function Invoke-Cleanup {
    # Remove the remote diag directory and all captured output files.
    # Uses Invoke-RemoteCimProcess so it works even if C$ is unavailable.
    # Fires-and-forgets — we do not poll for completion.
    if ($Script:CimSession) {
        try {
            $cleanCmd = "C:\Windows\System32\cmd.exe /c rmdir /s /q `"$RemoteDiagDir`""
            Invoke-RemoteCimProcess -CommandLine $cleanCmd -Description 'cleanup diag dir' | Out-Null
        } catch {}

        try { Remove-CimSession -CimSession $Script:CimSession -ErrorAction SilentlyContinue } catch {}
        $Script:CimSession = $null
    }
}

#endregion

#region ── MAIN ORCHESTRATOR ─────────────────────────────────────────────────────

function Test-FlexeraZFARequirements {
    Write-Host @"

══════════════════════════════════════════════════════════════════
  Flexera Zero Footprint Agent — Windows Requirements Diagnostic
  Target  : $TargetComputer
  Beacon  : $BeaconHostname
  Upload  : $UploadLocation
  Run as  : $(if ($Credential) { $Credential.UserName } else { [System.Security.Principal.WindowsIdentity]::GetCurrent().Name })
  Time    : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
══════════════════════════════════════════════════════════════════
"@ -ForegroundColor DarkCyan

    try {
        # ── Section 1: Local reachability
        Test-DNSLocal
        Test-PingInfo
        Test-TCPPorts

        # ── Section 2: SMB / Admin$
        Test-AdminShareRW
        Test-CShareRead

        # ── Section 3: Remote execution
        Test-RemoteExecution

        # ── Section 4: Target-side checks (requires sections 2+3)
        $smokeResult   = $Script:Results | Where-Object { $_.Test -eq 'Remote process creation (smoke test)' } | Select-Object -Last 1
        $adminResult   = $Script:Results | Where-Object { $_.Test -eq 'Admin$ read/write' } | Select-Object -Last 1
        $canRemoteExec = ($smokeResult -ne $null) -and ($smokeResult.Result -eq $PASS)
        $hasAdminShare = ($adminResult -ne $null) -and ($adminResult.Result -eq $PASS)

        if ($canRemoteExec -and $hasAdminShare) {
            Test-TargetSideDNS
            Test-TargetUNCRead
            Test-TargetHTTPUploadLocation

            # ── Section 5: ndtrack execution
            Invoke-NdtrackUNC
            Invoke-NdtrackLocalStaged

            # ── Section 6: Log tail
            Show-TrackerLogTail
        } else {
            @('Target-side DNS', 'Target→UNC read', 'Target→HTTP', 'ndtrack UNC', 'ndtrack staged', 'tracker.log') |
            ForEach-Object {
                Add-Result -Category 'Skipped' -Test $_ -Result $SKIP `
                    -Detail 'Skipped — prerequisite (remote exec or Admin$) failed'
            }
        }
    } catch {
        Write-Warning "Unexpected error during diagnostic run: $($_.Exception.Message)"
        Add-Result -Category 'Script' -Test 'Unhandled exception' -Result $FAIL `
            -Detail $_.Exception.Message
    } finally {
        Invoke-Cleanup
    }

    # ── Summary
    Write-SummaryTable
    Get-RemediationHints

    # ── Report output
    $reportPath = Resolve-ReportPath
    if ($reportPath) {
        if ($ReportFormat -eq 'CSV') {
            Export-CsvReport -Path $reportPath
        } else {
            # Try HTML; fall back to CSV if the write fails (permissions, disk full, etc.)
            try {
                Export-HtmlReport -Path $reportPath
            } catch {
                $csvFallback = [IO.Path]::ChangeExtension($reportPath, 'csv')
                Write-Warning "HTML report failed ('$($_.Exception.Message)') — falling back to CSV: $csvFallback"
                Export-CsvReport -Path $csvFallback
            }
        }
    }

    # ── Return results object for pipeline use
    return $Script:Results
}

#endregion

# ── ENTRY POINT ──────────────────────────────────────────────────────────────────
#
# Routing logic:
#   $_IsBatchJob = $true   → This instance was spawned by the CSV orchestrator.
#                            Run single-target mode immediately (no orchestration).
#   $RunMode = 'Single'    → Interactive single-target run. Run once and exit.
#   $RunMode = 'Csv'       → Load CSV and run each target — sequentially if
#                            $MaxParallelJobs -le 1, or in parallel via Start-Job.
#

if ($_IsBatchJob -or $RunMode -eq 'Single') {
    # ── SINGLE TARGET MODE (also used by each parallel batch job subprocess) ──────
    Test-FlexeraZFARequirements

} elseif ($RunMode -eq 'Csv') {
    # ── CSV MULTI-TARGET MODE ─────────────────────────────────────────────────────

    if (-not (Test-Path -LiteralPath $TargetCsvPath -ErrorAction SilentlyContinue)) {
        Write-Error "CSV file not found: $TargetCsvPath"
        exit 1
    }

    $csvRows = Import-Csv -LiteralPath $TargetCsvPath
    if (-not $csvRows) {
        Write-Error "CSV file is empty or could not be parsed: $TargetCsvPath"
        exit 1
    }

    # Validate that ComputerName column exists
    $firstRow = $csvRows | Select-Object -First 1
    if (-not ($firstRow.PSObject.Properties.Name -contains 'ComputerName')) {
        Write-Error "CSV must have a 'ComputerName' column. Found columns: $($firstRow.PSObject.Properties.Name -join ', ')"
        exit 1
    }

    $targets = $csvRows | Where-Object { $_.ComputerName -and $_.ComputerName.Trim() -ne '' }
    Write-Host "`nCSV loaded: $($targets.Count) target(s) from $TargetCsvPath" -ForegroundColor Cyan

    # ── Serialise credential once so batch jobs can reuse it without re-prompting ──
    # DPAPI (ConvertFrom-SecureString with no key) encrypts using the current Windows
    # user account. The spawned jobs run under the same user, so they can decrypt it.
    $serialisedCredUser = ''
    $serialisedCredPass = ''
    if ($Credential) {
        $serialisedCredUser = $Credential.UserName
        $serialisedCredPass = $Credential.Password | ConvertFrom-SecureString   # DPAPI encrypt
    }

    # ── Ensure report output directory exists (ask once, before spawning any jobs) ──
    if ($ReportOutputDir -and -not (Test-Path -LiteralPath $ReportOutputDir -ErrorAction SilentlyContinue)) {
        $answer = Read-Host "`n  Report directory '$ReportOutputDir' does not exist. Create it? [Y/N]"
        if ($answer -match '^[Yy]') {
            try {
                New-Item -Path $ReportOutputDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
                Write-Host "  Created report directory: $ReportOutputDir" -ForegroundColor Cyan
            } catch {
                Write-Warning "Could not create '$ReportOutputDir': $($_.Exception.Message). Reports will be skipped."
            }
        } else {
            Write-Host "  Reports will be skipped — directory not created." -ForegroundColor Yellow
        }
    }

    # ── Helper: build argument list for a single target row ───────────────────────
    function Build-TargetArgs {
        param($row)

        function Get-Col { param($r, $name)
            $prop = $r.PSObject.Properties | Where-Object { $_.Name -ieq $name } | Select-Object -First 1
            if ($prop) { return $prop.Value } else { return '' }
        }

        # Per-row ReportPath override; if blank, Resolve-ReportPath in the subprocess
        # will auto-name using $ReportOutputDir (passed through as the config default).
        $reportPath = (Get-Col $row 'ReportPath').Trim()

        return @{
            _CsvTargetComputer  = $row.ComputerName.Trim()
            _CsvBeaconHostname  = (Get-Col $row 'BeaconHostname').Trim()
            _CsvUploadServer    = (Get-Col $row 'UploadServer').Trim()
            _CsvUploadProtocol  = (Get-Col $row 'UploadProtocol').Trim()
            _CsvUploadPort      = (Get-Col $row 'UploadPort').Trim()
            _CsvHtmlReportPath  = $reportPath
            _CsvCredUser        = $serialisedCredUser
            _CsvCredPass        = $serialisedCredPass
        }
    }

    $scriptPath = $PSCommandPath   # Full path to this script file

    if ($MaxParallelJobs -le 1) {
        # ── SEQUENTIAL ────────────────────────────────────────────────────────────
        Write-Host "Running sequentially (MaxParallelJobs = $MaxParallelJobs)" -ForegroundColor DarkCyan
        foreach ($row in $targets) {
            $args = Build-TargetArgs $row
            Write-Host "`n═══ TARGET: $($args._CsvTargetComputer) ═══" -ForegroundColor Cyan
            & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass `
                -File $scriptPath `
                -_CsvTargetComputer $args._CsvTargetComputer `
                -_CsvBeaconHostname $args._CsvBeaconHostname `
                -_CsvUploadServer   $args._CsvUploadServer   `
                -_CsvUploadProtocol $args._CsvUploadProtocol `
                -_CsvUploadPort     $args._CsvUploadPort     `
                -_CsvHtmlReportPath $args._CsvHtmlReportPath `
                -_CsvCredUser       $args._CsvCredUser       `
                -_CsvCredPass       $args._CsvCredPass
        }
    } else {
        # ── PARALLEL via Start-Job ────────────────────────────────────────────────
        Write-Host "Running in parallel (MaxParallelJobs = $MaxParallelJobs)" -ForegroundColor DarkCyan

        $pending  = [System.Collections.Generic.Queue[object]]::new()
        foreach ($row in $targets) { $pending.Enqueue($row) }

        $running  = [System.Collections.Generic.List[object]]::new()
        $allJobs  = [System.Collections.Generic.List[object]]::new()

        while ($pending.Count -gt 0 -or $running.Count -gt 0) {

            # Fill up to MaxParallelJobs
            while ($pending.Count -gt 0 -and $running.Count -lt $MaxParallelJobs) {
                $row  = $pending.Dequeue()
                $tArgs = Build-TargetArgs $row
                $target = $tArgs._CsvTargetComputer

                Write-Host "  → Starting job for $target" -ForegroundColor Cyan

                $job = Start-Job -ScriptBlock {
                    param($sp, $a)
                    & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass `
                        -File $sp `
                        -_CsvTargetComputer $a._CsvTargetComputer `
                        -_CsvBeaconHostname $a._CsvBeaconHostname `
                        -_CsvUploadServer   $a._CsvUploadServer   `
                        -_CsvUploadProtocol $a._CsvUploadProtocol `
                        -_CsvUploadPort     $a._CsvUploadPort     `
                        -_CsvHtmlReportPath $a._CsvHtmlReportPath `
                        -_CsvCredUser       $a._CsvCredUser       `
                        -_CsvCredPass       $a._CsvCredPass
                } -ArgumentList $scriptPath, $tArgs

                $running.Add([PSCustomObject]@{ Job = $job; Target = $target })
                $allJobs.Add([PSCustomObject]@{ Job = $job; Target = $target })
            }

            # Check for completed jobs
            $completed = $running | Where-Object { $_.Job.State -in @('Completed', 'Failed', 'Stopped') }
            foreach ($item in $completed) {
                Write-Host "`n═══ RESULTS: $($item.Target) ═══" -ForegroundColor Yellow
                Receive-Job -Job $item.Job
                $running.Remove($item) | Out-Null
            }

            if ($running.Count -ge $MaxParallelJobs -or ($pending.Count -eq 0 -and $running.Count -gt 0)) {
                Start-Sleep -Seconds 5
            }
        }

        # Final cleanup
        $allJobs | ForEach-Object { Remove-Job -Job $_.Job -Force -ErrorAction SilentlyContinue }
    }

    Write-Host "`n═══ ALL TARGETS COMPLETE ═══" -ForegroundColor Green
    if ($ReportOutputDir -and (Test-Path -LiteralPath $ReportOutputDir -ErrorAction SilentlyContinue)) {
        Write-Host "  Reports saved to: $ReportOutputDir" -ForegroundColor Cyan
    }

} else {
    Write-Error "Invalid `$RunMode value: '$RunMode'. Expected 'Single' or 'Csv'."
    exit 1
}