
#Requires -Version 5.1
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
    Version : 2.2
    Requires: PowerShell 5.1+, run elevated on the machine performing the scan.
    Target  : Windows hosts (Flexera FNMS 2023 R2 ZFA requirements)

    Reference:
        https://docs.flexera.com/FlexNetManagerSuite2023R2/EN/GatherFNInv/index.html
        #SysRef/FlexNetInventoryAgent/topics/ZFA-SystemReqs.html

    ── IMPROVEMENT NOTES vs prior version ──────────────────────────────────────────
    [+] CIM sessions (Get-CimInstance / New-CimSession) replace deprecated Get-WmiObject.
        CIM tries WSMAN first then falls back to DCOM — more reliable across environments.
    [+] Test-NetConnection replaces raw socket code for port tests (cleaner, built-in).
    [+] Result objects are structured [PSCustomObject] throughout — pipe to Export-Csv etc.
    [+] HTML report for sharing with firewall/network teams.
    [+] Timeout guard on WMI remote process waits (prevents indefinite hangs).
    [+] PS 5.1 compatible — no null-coalescing (??), ternary (? :), or null-conditional (?.)

    ── v2.2 CHANGES ────────────────────────────────────────────────────────────────
    [fix] Removed dead $DiagDirRemoteAdmin variable (never referenced).
    [fix] Admin$ now mounted as a persistent PSDrive (Mount-AdminShare) for the full
          run so Read-RemoteTextViaAdmin and staged copies use the same authenticated
          session rather than mixing credential and no-credential UNC access.
    [fix] Test-CShareRead now closes the FileStream in a finally block (was leaking handle).
    [fix] Invoke-NdtrackLocalStaged now checks $proc.Launched before reading output files.
    [fix] Null-check order in prerequisite guards uses ($null -ne $x) to be strict-mode safe.
    [new] Elevation check at startup — exits immediately with a clear message if not admin.
    [new] Optional PowerShell transcript ($TranscriptPath) for full session capture.
    [new] Optional remote temp dir cleanup after the run ($CleanupRemoteDiagDir, default $true).
    [new] Section 4/5 (target-side checks) now gated on remote exec only; tracker.log
          (Section 6) gated on Admin$ only — the two prerequisites are evaluated independently.
    ────────────────────────────────────────────────────────────────────────────────
#>

#region ── USER CONFIGURATION ────────────────────────────────────────────────────
# Edit the values in this section before running the script.

# Hostname, FQDN, or IP of the Windows machine to scan agentlessly.
$TargetComputer      = 'WORKSTATION01'

# Hostname, FQDN, or IP of the Flexera Beacon server that hosts mgsRET$.
$BeaconHostname      = 'BEACON01'

# Hostname, FQDN, or IP of the server hosting ManageSoftRL.
# The full upload URL is built automatically: http://<value>/ManageSoftRL
$UploadServer        = 'BEACON01'

# Username for Admin$ / WMI authentication (e.g. 'DOMAIN\username' or 'hostname\localadmin').
# Leave empty ('') to run under the current user context without a password prompt.
$CredentialUsername  = 'DOMAIN\username'

# Path to ndtrack.exe relative to \\BeaconHostname\mgsRET$
$NdtrackRelativePath = 'Inventory\ndtrack.exe'

# Set to $true to copy ndtrack.exe locally to the target and run it from there.
# Useful when UNC execution is blocked by AppLocker/WDAC/EDR.
$StageNdtrackLocally = $false

# Set to $true to skip launching ndtrack.exe entirely (safe/read-only mode).
$SkipNdtrackExecution = $false

# Optional: full path to write an HTML report. Leave empty '' to skip.
# Example: 'C:\Diag\ZFP_WORKSTATION01.html'
$HtmlReportPath      = ''

# Set to $true to remove the remote temp folder from the target after the run.
# Set to $false to keep files in place for manual debugging.
$CleanupRemoteDiagDir = $true

# Optional: full path to write a PowerShell transcript of this run. Leave empty '' to skip.
# Example: 'C:\Diag\ZFP_WORKSTATION01_transcript.txt'
$TranscriptPath       = ''

# Temp directory created on the target for capturing command output files.
$RemoteDiagDir       = 'C:\Windows\Temp\FlexeraZFPDiag'

#endregion ── END USER CONFIGURATION ─────────────────────────────────────────────

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region ── DERIVED VARIABLES & STATE ─────────────────────────────────────────────────────

# Build the full UploadLocation URL from the server value set above.
$UploadLocation = "http://$UploadServer/ManageSoftRL"

# Build the full ndtrack UNC path.
$NdtrackUNC     = "\\$BeaconHostname\mgsRET`$\$NdtrackRelativePath"

# Prompt for password if a username was supplied; otherwise run as current user.
if ($CredentialUsername -ne '') {
    $Credential = Get-Credential -UserName $CredentialUsername `
                                 -Message "Enter password for $CredentialUsername (used for Admin$ and WMI access to $TargetComputer)"
} else {
    $Credential = $null
}

$Script:Results        = [System.Collections.Generic.List[PSObject]]::new()
$Script:AdminDriveName = $null   # PSDrive name if Admin$ is persistently mounted
$Script:CimSession     = $null   # Reusable CIM session

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
    Returns a CIM session to the target, trying WSMan (WinRM) first then DCOM fallback.
    Session is cached in $Script:CimSession.
    IMPROVEMENT: CIM over WSMan is faster and less firewall-sensitive than raw DCOM;
                 the automatic fallback means one function works in both environments.
#>
function Get-TargetCimSession {
    if ($Script:CimSession -and $Script:CimSession.TestConnection()) {
        return $Script:CimSession
    }

    $cimOpts = @{ ComputerName = $TargetComputer; ErrorAction = 'Stop' }
    if ($Credential) { $cimOpts['Credential'] = $Credential }

    # Try DCOM first (TCP 135 + dynamic RPC) — this is the transport Flexera Beacon
    # uses for Win32_Process.Create. WSMan (WinRM/5985) is attempted as a fallback
    # only; a WSMan-only success would indicate the Beacon path may still be broken.
    foreach ($proto in @('Dcom', 'Wsman')) {
        try {
            $sessionOpt = New-CimSessionOption -Protocol $proto
            $cimOpts['SessionOption'] = $sessionOpt
            $Script:CimSession = New-CimSession @cimOpts
            return $Script:CimSession
        } catch {
            # Try next protocol
        }
    }
    throw "Unable to establish CIM session via DCOM or WSMan to $TargetComputer"
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

    $wrapped = "cmd /c `"$InnerCommand`" > `"$stdoutFile`" 2> `"$stderrFile`" & echo %errorlevel% > `"$exitFile`""

    $launchResult = Invoke-RemoteCimProcess -CommandLine $wrapped -Description $Tag
    if ($launchResult.ReturnCode -ne 0) {
        return [PSCustomObject]@{
            Launched    = $false
            LaunchError = "$($launchResult.ReturnText) | $($launchResult.Error)"
            StdoutFile  = $stdoutFile
            StderrFile  = $stderrFile
            ExitFile    = $exitFile
            ProcessId   = $null
        }
    }

    # Poll for process exit (avoid indefinite hang)
    $deadline = [datetime]::UtcNow.AddSeconds($TimeoutSec)
    do {
        Start-Sleep -Seconds 3
        try {
            $session = Get-TargetCimSession
            $running = Get-CimInstance -CimSession $session -ClassName Win32_Process `
                       -Filter "ProcessId = $($launchResult.ProcessId)" -ErrorAction SilentlyContinue
        } catch { $running = $null }
    } while ($running -and [datetime]::UtcNow -lt $deadline)

    return [PSCustomObject]@{
        Launched    = $true
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
    Maps \\Target\Admin$ to a persistent PSDrive (ZFPDiag:) for the lifetime of
    the script run, using $Credential when provided. Subsequent UNC reads and
    copies all route through this authenticated drive so credentials are applied
    consistently. The drive is removed in Invoke-Cleanup.
    Returns $true on success, $false on failure.
#>
function Mount-AdminShare {
    $driveName = 'ZFPDiag'
    if (Get-PSDrive -Name $driveName -ErrorAction SilentlyContinue) {
        $Script:AdminDriveName = $driveName
        return $true
    }
    $mapArgs = @{ Name = $driveName; PSProvider = 'FileSystem'; Root = "\\$TargetComputer\Admin$"; ErrorAction = 'Stop' }
    if ($Credential) { $mapArgs['Credential'] = $Credential }
    try {
        New-PSDrive @mapArgs | Out-Null
        $Script:AdminDriveName = $driveName
        return $true
    } catch {
        $Script:AdminDriveName = $null
        return $false
    }
}

<#
.DESCRIPTION
    Reads a remote file back via Admin$ (C:\Windows\... → Admin$\...).
    Uses the persistent PSDrive (ZFPDiag:) when mounted so that credential-based
    authentication is applied consistently; falls back to raw UNC otherwise.
    Returns the content as a string, or $null on failure.
#>
function Read-RemoteTextViaAdmin {
    param([string]$RemotePath)   # e.g. C:\Windows\Temp\FlexeraZFPDiag\foo.txt
    $relative = $RemotePath -replace '^C:\\', ''
    try {
        if ($Script:AdminDriveName) {
            return (Get-Content -LiteralPath "${Script:AdminDriveName}:\$relative" -Raw -ErrorAction Stop)
        }
        return (Get-Content -LiteralPath "\\$TargetComputer\Admin$\$relative" -Raw -ErrorAction Stop)
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
    $candidates = @(
        "\\$TargetComputer\C$\Windows\Temp\ManageSoft\tracker.log",
        "\\$TargetComputer\C$\ProgramData\Flexera Software\Compliance\Logging\tracker.log",
        "\\$TargetComputer\C$\Program Files (x86)\ManageSoft\tracker.log"
    )
    foreach ($path in $candidates) {
        try {
            $content = Get-Content -LiteralPath $path -Tail $Lines -ErrorAction Stop
            return [PSCustomObject]@{ Path = $path; Lines = $content }
        } catch { }
    }
    return $null
}

#endregion

#region ── SECTION 1: LOCAL REACHABILITY ─────────────────────────────────────────

function Test-DNSLocal {
    Write-Host "`n── [1] LOCAL REACHABILITY ──────────────────────────────────────" -ForegroundColor DarkCyan
    try {
        $resolved = [System.Net.Dns]::GetHostAddresses($TargetComputer)
        $ips      = ($resolved | ForEach-Object { $_.IPAddressToString }) -join ', '
        Add-Result -Category 'DNS' -Test 'Resolve target name' -Result $PASS -Detail $ips
    } catch {
        Add-Result -Category 'DNS' -Test 'Resolve target name' -Result $FAIL `
            -Detail $_.Exception.Message `
            -Hint 'Fix DNS/hosts file before any other test can succeed.'
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
    $tag      = [guid]::NewGuid().ToString('N').Substring(0,8)
    try {
        if (-not (Mount-AdminShare)) { throw "Failed to mount \\$TargetComputer\Admin$" }
        $drivePath = "${Script:AdminDriveName}:\Temp\ZFPDiagTest_${tag}.tmp"
        # Write test
        Set-Content  -LiteralPath $drivePath -Value 'ZFP_DIAG_OK' -ErrorAction Stop
        # Read back
        $content = Get-Content -LiteralPath $drivePath -Raw -ErrorAction Stop
        # Delete
        Remove-Item  -LiteralPath $drivePath -Force -ErrorAction SilentlyContinue
        if ($content -notmatch 'ZFP_DIAG_OK') { throw 'Read-back content mismatch' }
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
        if ($proto -eq 'Dcom') {
            Add-Result -Category 'WMI/CIM' -Test 'CIM session established' -Result $PASS `
                -Detail "Connected via DCOM (matches Flexera Beacon transport)"
        } else {
            Add-Result -Category 'WMI/CIM' -Test 'CIM session established' -Result $WARN `
                -Detail "Connected via $proto — DCOM failed, fell back to WSMan. Flexera Beacon uses DCOM; this result may not reflect real inventory behaviour." `
                -Hint 'Check TCP 135 and dynamic RPC port range (49152-65535) to the target. DCOM Launch/Activation permissions in Component Services may also be blocking.'
        }
    } catch {
        Add-Result -Category 'WMI/CIM' -Test 'CIM session established' -Result $FAIL `
            -Detail $_.Exception.Message `
            -Hint 'Ensure TCP 135 is open, DCOM/WMI service is running, and credentials are valid.'
        return  # Nothing further will work
    }

    # 3b. Smoke test: create diag directory on target
    $mkdirCmd = "cmd /c mkdir `"$RemoteDiagDir`" 2>nul"
    $r        = Invoke-RemoteCimProcess -CommandLine $mkdirCmd -Description 'mkdir diag dir'
    if ($r.ReturnCode -eq 0) {
        Add-Result -Category 'WMI/CIM' -Test 'Remote process creation (smoke test)' -Result $PASS `
            -Detail "Win32_Process.Create returned 0 (Success) — PID $($r.ProcessId)"
    } else {
        Add-Result -Category 'WMI/CIM' -Test 'Remote process creation (smoke test)' -Result $FAIL `
            -Detail "$($r.ReturnText) | $($r.Error)" `
            -Hint   'Check DCOM Launch/Access permissions in Component Services. Verify WMI service on target.'
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
                -InnerCommand "nslookup $BeaconHostname" -TimeoutSec 30
    if (-not $proc.Launched) {
        Add-Result -Category 'Target→DNS' -Test "Resolve BeaconHost ($BeaconHostname)" `
            -Result $FAIL -Detail "Launch failed: $($proc.LaunchError)" `
            -Hint 'Remote process creation failed before DNS could be tested.'
        return
    }
    $out = Read-RemoteTextViaAdmin -RemotePath $proc.StdoutFile
    $err = Read-RemoteTextViaAdmin -RemotePath $proc.StderrFile
    $exit= Read-RemoteTextViaAdmin -RemotePath $proc.ExitFile

    if ($out -match 'Address:') {
        Add-Result -Category 'Target→DNS' -Test "Resolve BeaconHost ($BeaconHostname)" `
            -Result $PASS -Detail (($out -split "`n" | Select-Object -Last 3) -join ' | ')
    } else {
        Add-Result -Category 'Target→DNS' -Test "Resolve BeaconHost ($BeaconHostname)" `
            -Result $FAIL `
            -Detail "stdout: $(if ($out) { $out.Trim() }) | stderr: $(if ($err) { $err.Trim() })" `
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
    # Can the target reach the ManageSoftRL endpoint?
    $psCmd  = "powershell -NonInteractive -Command `"try { Invoke-WebRequest -Uri '$UploadLocation' -UseBasicParsing -TimeoutSec 15 -ErrorAction Stop | Select-Object -ExpandProperty StatusCode } catch { Write-Error `$_.Exception.Message; exit 1 }`""
    $proc   = Invoke-RemoteCapturedProcess -Tag 'http_upload' -InnerCommand $psCmd -TimeoutSec 45

    if (-not $proc.Launched) {
        Add-Result -Category 'Target→HTTP' -Test "Reach UploadLocation" `
            -Result $FAIL -Detail "Launch failed: $($proc.LaunchError)" `
            -Hint 'Remote process creation failed before HTTP test could run.'
        return
    }
    $out  = Read-RemoteTextViaAdmin -RemotePath $proc.StdoutFile
    $err  = Read-RemoteTextViaAdmin -RemotePath $proc.StderrFile
    $exit = $null; $rawExit = Read-RemoteTextViaAdmin -RemotePath $proc.ExitFile; if ($rawExit) { $exit = $rawExit.Trim() }

    $statusCode = ($out -split '\r?\n' | Where-Object { $_ -match '^\d{3}$' } | Select-Object -First 1)

    if ($exit -eq '0' -and $statusCode) {
        $resultCode = if ($statusCode -in @('200','301','302','401','403')) { $PASS } else { $WARN }
        $httpHint   = if ($resultCode -eq $WARN) { "Unexpected status $statusCode — verify URL is correct." } else { '' }
        Add-Result -Category 'Target→HTTP' -Test "Reach UploadLocation" `
            -Result $resultCode `
            -Detail "HTTP $statusCode from $UploadLocation" `
            -Hint   $httpHint
    } else {
        $errTrimmed = if ($err) { $err.Trim() } else { '' }
        Add-Result -Category 'Target→HTTP' -Test "Reach UploadLocation" `
            -Result $FAIL `
            -Detail "Exit $exit | stderr: $errTrimmed" `
            -Hint "Target cannot reach UploadLocation. Check firewall rules from target subnet to Beacon HTTP port."
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

    # Minimal args — enough to get a log entry without a full inventory run
    $ndArgs  = "MachineID=ZFPDiag_Test UploadLocation=`"$UploadLocation`" LogFile=`"$RemoteDiagDir\ndtrack.log`""
    $ndCmd   = "`"$NdtrackUNC`" $ndArgs"

    $proc = Invoke-RemoteCapturedProcess -Tag 'ndtrack_unc' -InnerCommand $ndCmd -TimeoutSec 180

    if (-not $proc.Launched) {
        Add-Result -Category 'ndtrack' -Test 'UNC launch (Beacon-style)' `
            -Result $FAIL -Detail "Launch failed: $($proc.LaunchError)" `
            -Hint 'Win32_Process.Create could not launch UNC exe. AppLocker/WDAC/EDR may be blocking UNC execution.'
        return
    }

    $stdout = Read-RemoteTextViaAdmin -RemotePath $proc.StdoutFile
    $stderr = Read-RemoteTextViaAdmin -RemotePath $proc.StderrFile
    $exit   = $null; $rawExit1 = Read-RemoteTextViaAdmin -RemotePath $proc.ExitFile; if ($rawExit1) { $exit = $rawExit1.Trim() }

    $stdoutTrimmed = if ($stdout) { $stdout.Trim().Substring(0, [Math]::Min(200, $stdout.Length)) } else { '' }
    $detail = "Exit $exit | stdout: $stdoutTrimmed"

    if ($exit -eq '0') {
        Add-Result -Category 'ndtrack' -Test 'UNC launch (Beacon-style)' -Result $PASS -Detail $detail
    } elseif ($null -eq $exit) {
        Add-Result -Category 'ndtrack' -Test 'UNC launch (Beacon-style)' -Result $WARN `
            -Detail 'Process launched but exit code not captured (timeout?)' `
            -Hint 'ndtrack may still be running or timed out. Check tracker.log.'
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
}

function Invoke-NdtrackLocalStaged {
    if ($SkipNdtrackExecution) { return }
    if (-not $StageNdtrackLocally) { return }

    Write-Host "`n── [5b] NDTRACK STAGED LOCAL RUN ───────────────────────────────" -ForegroundColor DarkCyan

    # Stage: copy ndtrack.exe from Beacon share to target via Admin$
    $localExe = "$RemoteDiagDir\ndtrack_staged.exe"
    if ($Script:AdminDriveName) {
        $adminDest = $localExe -replace '^C:\\', "${Script:AdminDriveName}:\"
    } else {
        $adminDest = $localExe -replace '^C:\\', "\\$TargetComputer\Admin$\"
    }

    try {
        Copy-Item -LiteralPath $NdtrackUNC -Destination $adminDest -Force -ErrorAction Stop
        Add-Result -Category 'ndtrack' -Test 'Stage ndtrack.exe locally' -Result $PASS `
            -Detail "Copied to $localExe on target"
    } catch {
        Add-Result -Category 'ndtrack' -Test 'Stage ndtrack.exe locally' -Result $FAIL `
            -Detail $_.Exception.Message `
            -Hint 'Could not copy ndtrack.exe — check Beacon share read access and Admin$ write access.'
        return
    }

    # Run from local path
    $ndArgs = "MachineID=ZFPDiag_Staged UploadLocation=`"$UploadLocation`" LogFile=`"$RemoteDiagDir\ndtrack_staged.log`""
    $proc   = Invoke-RemoteCapturedProcess -Tag 'ndtrack_local' `
                  -InnerCommand "`"$localExe`" $ndArgs" -TimeoutSec 180

    if (-not $proc.Launched) {
        Add-Result -Category 'ndtrack' -Test 'Staged local run' -Result $FAIL `
            -Detail "Launch failed: $($proc.LaunchError)" `
            -Hint 'Win32_Process.Create could not launch the staged executable.'
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
    Write-Host "`n── [6] TRACKER.LOG (last 30 lines) ─────────────────────────────" -ForegroundColor DarkCyan
    $tail = Get-RemoteTrackerLogTail -Lines 30
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

#region ── HTML REPORT ───────────────────────────────────────────────────────────

<#
.DESCRIPTION
    IMPROVEMENT: HTML report output so results can be shared with firewall / network
    teams without them needing PowerShell access.
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
    try {
        [IO.File]::WriteAllText($Path, $html)
        Write-Host "`n  HTML report saved: $Path" -ForegroundColor Cyan
    } catch {
        Write-Warning "Could not write HTML report to $Path — $($_.Exception.Message)"
    }
}

#endregion

#region ── CLEANUP ───────────────────────────────────────────────────────────────

function Invoke-Cleanup {
    # Remove remote diag directory from target if requested (Enhancement 6)
    if ($CleanupRemoteDiagDir -and $Script:CimSession) {
        try {
            $cleanCmd = "cmd /c rmdir /s /q `"$RemoteDiagDir`""
            Invoke-RemoteCimProcess -CommandLine $cleanCmd | Out-Null
            Add-Result -Category 'Cleanup' -Test 'Remove remote diag dir' -Result $INFO `
                -Detail $RemoteDiagDir
        } catch { }
    }
    if ($Script:CimSession) {
        try { Remove-CimSession -CimSession $Script:CimSession -ErrorAction SilentlyContinue } catch {}
        $Script:CimSession = $null
    }
    # Unmount the persistent Admin$ PSDrive
    if ($Script:AdminDriveName -and (Get-PSDrive -Name $Script:AdminDriveName -ErrorAction SilentlyContinue)) {
        Remove-PSDrive -Name $Script:AdminDriveName -Force -ErrorAction SilentlyContinue
        $Script:AdminDriveName = $null
    }
}

#endregion

#region ── MAIN ORCHESTRATOR ─────────────────────────────────────────────────────

function Test-FlexeraZFARequirements {
    # ── Elevation check (Enhancement 5)
    $isElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
                   [Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isElevated) {
        Write-Warning 'This script must be run from an elevated (Run as Administrator) PowerShell session. Exiting.'
        return
    }

    # ── Transcript (Enhancement 7)
    if ($TranscriptPath) {
        Start-Transcript -Path $TranscriptPath -Force -ErrorAction SilentlyContinue
    }

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

        # ── Evaluate prerequisites for downstream sections independently (Enhancement 8)
        $smokeResult   = $Script:Results | Where-Object { $_.Test -eq 'Remote process creation (smoke test)' } | Select-Object -Last 1
        $adminResult   = $Script:Results | Where-Object { $_.Test -eq 'Admin$ read/write' } | Select-Object -Last 1
        $canRemoteExec = ($null -ne $smokeResult) -and ($smokeResult.Result -eq $PASS)
        $hasAdminShare = ($null -ne $adminResult) -and ($adminResult.Result -eq $PASS)

        # ── Section 4+5: Target-side checks and ndtrack (require remote exec only;
        #    Admin$ failures surface in individual test details rather than blocking all tests)
        if ($canRemoteExec) {
            Test-TargetSideDNS
            Test-TargetUNCRead
            Test-TargetHTTPUploadLocation

            # ── Section 5: ndtrack execution
            Invoke-NdtrackUNC
            Invoke-NdtrackLocalStaged
        } else {
            @('Target-side DNS', 'Target→UNC read', 'Target→HTTP', 'ndtrack UNC', 'ndtrack staged') |
            ForEach-Object {
                Add-Result -Category 'Skipped' -Test $_ -Result $SKIP `
                    -Detail 'Skipped — remote process creation failed'
            }
        }

        # ── Section 6: Log tail (requires Admin$/C$ only — independent of remote exec)
        if ($hasAdminShare) {
            Show-TrackerLogTail
        } else {
            Add-Result -Category 'Skipped' -Test 'tracker.log' -Result $SKIP `
                -Detail 'Skipped — Admin$ not accessible'
        }
    } catch {
        Write-Warning "Unexpected error during diagnostic run: $($_.Exception.Message)"
        Add-Result -Category 'Script' -Test 'Unhandled exception' -Result $FAIL `
            -Detail $_.Exception.Message
    } finally {
        Invoke-Cleanup
        if ($TranscriptPath) { try { Stop-Transcript } catch {} }
    }

    # ── Summary
    Write-SummaryTable
    Get-RemediationHints

    # ── HTML report
    if ($HtmlReportPath) {
        Export-HtmlReport -Path $HtmlReportPath
    }

    # ── Return results object for pipeline use
    return $Script:Results
}

#endregion

# ── ENTRY POINT ──────────────────────────────────────────────────────────────────
Test-FlexeraZFARequirements
