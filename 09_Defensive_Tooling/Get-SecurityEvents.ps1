<#
.SYNOPSIS
    Security Event Monitor — Detects brute-force and suspicious authentication patterns
    from Windows Security event logs.

.DESCRIPTION
    Queries the Windows Security event log for:
    - Event ID 4625: Failed logon attempts
    - Event ID 4624: Successful logon events
    Implements threshold-based alerting to detect brute-force activity.
    Generates alerts when failed login count exceeds threshold within the time window.

.PARAMETER FailureThreshold
    Number of failed logins within the time window to trigger an alert. Default: 10.

.PARAMETER TimeWindowMinutes
    Time window in minutes for brute-force detection. Default: 5.

.PARAMETER LogPath
    Path to write the alert log. Default: .\SecurityAlerts.log

.PARAMETER WatchIntervalSeconds
    How often (in seconds) to poll for new events in continuous mode. Default: 60.

.PARAMETER Continuous
    If specified, runs in continuous polling mode until Ctrl+C is pressed.

.EXAMPLE
    # One-time scan of last 60 minutes
    .\Get-SecurityEvents.ps1 -FailureThreshold 5 -TimeWindowMinutes 60

.EXAMPLE
    # Continuous monitoring mode
    .\Get-SecurityEvents.ps1 -Continuous -WatchIntervalSeconds 30

.NOTES
    Author: CyberPath Defense Toolkit
    Requires: Administrator privileges to read Security event log
    Run: Set-ExecutionPolicy RemoteSigned -Scope CurrentUser (if needed)
#>

[CmdletBinding()]
param(
    [int]$FailureThreshold     = 10,
    [int]$TimeWindowMinutes    = 5,
    [string]$LogPath           = ".\SecurityAlerts.log",
    [int]$WatchIntervalSeconds = 60,
    [switch]$Continuous
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region --- Helper Functions ---

function Write-Log {
    <#
    .SYNOPSIS Writes a timestamped message to console and log file.#>
    param(
        [string]$Message,
        [ValidateSet('INFO','WARN','ALERT','ERROR')]
        [string]$Level = 'INFO'
    )
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "[$timestamp] [$Level] $Message"

    # Console output with color coding
    $color = switch ($Level) {
        'INFO'  { 'Cyan' }
        'WARN'  { 'Yellow' }
        'ALERT' { 'Red' }
        'ERROR' { 'Magenta' }
    }
    Write-Host $line -ForegroundColor $color

    # Append to log file
    try {
        Add-Content -Path $LogPath -Value $line -Encoding UTF8
    } catch {
        Write-Warning "Failed to write to log file: $_"
    }
}

function Test-AdminPrivilege {
    <#
    .SYNOPSIS Verifies the script is running with administrator privileges.#>
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-FailedLogons {
    <#
    .SYNOPSIS Retrieves Event ID 4625 (failed logon) records within the specified window.
    .PARAMETER Since DateTime representing the start of the query window.#>
    param([datetime]$Since)

    $filter = @{
        LogName   = 'Security'
        Id        = 4625
        StartTime = $Since
    }

    try {
        $events = Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue
        if (-not $events) { return @() }

        return $events | ForEach-Object {
            $xml = [xml]$_.ToXml()
            $data = $xml.Event.EventData.Data

            # Extract fields by name attribute
            $subjectUser  = ($data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
            $targetUser   = ($data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
            $workstation  = ($data | Where-Object { $_.Name -eq 'WorkstationName' }).'#text'
            $sourceIP     = ($data | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
            $logonType    = ($data | Where-Object { $_.Name -eq 'LogonType' }).'#text'
            $failureReason = ($data | Where-Object { $_.Name -eq 'FailureReason' }).'#text'

            [PSCustomObject]@{
                TimeCreated   = $_.TimeCreated
                EventId       = $_.Id
                SubjectUser   = $subjectUser
                TargetUser    = $targetUser
                Workstation   = $workstation
                SourceIP      = $sourceIP
                LogonType     = $logonType
                FailureReason = $failureReason
            }
        }
    } catch {
        Write-Log "Error querying failed logon events: $_" -Level ERROR
        return @()
    }
}

function Get-SuccessfulLogons {
    <#
    .SYNOPSIS Retrieves Event ID 4624 (successful logon) records within the specified window.#>
    param([datetime]$Since)

    $filter = @{
        LogName   = 'Security'
        Id        = 4624
        StartTime = $Since
    }

    try {
        $events = Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue
        if (-not $events) { return @() }

        return $events | ForEach-Object {
            $xml  = [xml]$_.ToXml()
            $data = $xml.Event.EventData.Data

            $targetUser  = ($data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
            $sourceIP    = ($data | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
            $workstation = ($data | Where-Object { $_.Name -eq 'WorkstationName' }).'#text'
            $logonType   = ($data | Where-Object { $_.Name -eq 'LogonType' }).'#text'

            [PSCustomObject]@{
                TimeCreated  = $_.TimeCreated
                EventId      = $_.Id
                TargetUser   = $targetUser
                SourceIP     = $sourceIP
                Workstation  = $workstation
                LogonType    = $logonType
            }
        }
    } catch {
        Write-Log "Error querying successful logon events: $_" -Level ERROR
        return @()
    }
}

function Invoke-BruteForceDetection {
    <#
    .SYNOPSIS Analyzes failed logon events and alerts if threshold is exceeded.
    .PARAMETER FailedLogons Collection of failed logon event objects.#>
    param(
        [array]$FailedLogons
    )

    if ($FailedLogons.Count -eq 0) { return }

    # Group failures by source IP
    $byIP = $FailedLogons | Where-Object { $_.SourceIP -and $_.SourceIP -ne '-' -and $_.SourceIP -ne '::1' } |
        Group-Object -Property SourceIP |
        Where-Object { $_.Count -ge $FailureThreshold }

    foreach ($group in $byIP) {
        $targetUsers = ($group.Group | Select-Object -ExpandProperty TargetUser -Unique) -join ', '
        Write-Log ("BRUTE-FORCE ALERT: IP {0} had {1} failed logins in {2} minutes. Targeted users: {3}" -f
            $group.Name, $group.Count, $TimeWindowMinutes, $targetUsers) -Level ALERT
    }

    # Group failures by target username
    $byUser = $FailedLogons | Group-Object -Property TargetUser |
        Where-Object { $_.Count -ge $FailureThreshold -and $_.Name -ne '-' }

    foreach ($group in $byUser) {
        $sourceIPs = ($group.Group | Select-Object -ExpandProperty SourceIP -Unique) -join ', '
        Write-Log ("PASSWORD-SPRAY ALERT: Account '{0}' had {1} failed logins in {2} minutes from IPs: {3}" -f
            $group.Name, $group.Count, $TimeWindowMinutes, $sourceIPs) -Level ALERT
    }
}

function Invoke-SuccessAfterFailureDetection {
    <#
    .SYNOPSIS Detects successful logins that follow multiple failed attempts (possible successful brute-force).#>
    param(
        [array]$FailedLogons,
        [array]$SuccessfulLogons
    )

    if ($FailedLogons.Count -eq 0 -or $SuccessfulLogons.Count -eq 0) { return }

    # Get usernames that had multiple failures
    $bruteTargets = $FailedLogons | Group-Object TargetUser |
        Where-Object { $_.Count -ge [math]::Max(3, $FailureThreshold / 2) } |
        Select-Object -ExpandProperty Name

    # Check if any of those users then succeeded
    foreach ($user in $bruteTargets) {
        $success = $SuccessfulLogons | Where-Object { $_.TargetUser -eq $user }
        if ($success) {
            $failCount = ($FailedLogons | Where-Object { $_.TargetUser -eq $user }).Count
            Write-Log ("BRUTE-FORCE SUCCESS: Account '{0}' had {1} failures then a SUCCESSFUL login from {2}" -f
                $user, $failCount, ($success | Select-Object -First 1).SourceIP) -Level ALERT
        }
    }
}

#endregion

#region --- Main Execution ---

function Invoke-SecurityEventScan {
    $since = (Get-Date).AddMinutes(-$TimeWindowMinutes)
    Write-Log "Scanning events since $($since.ToString('yyyy-MM-dd HH:mm:ss'))" -Level INFO

    $failedLogons     = Get-FailedLogons     -Since $since
    $successfulLogons = Get-SuccessfulLogons -Since $since

    Write-Log "Found $($failedLogons.Count) failed logon events, $($successfulLogons.Count) successful logon events" -Level INFO

    Invoke-BruteForceDetection          -FailedLogons $failedLogons
    Invoke-SuccessAfterFailureDetection -FailedLogons $failedLogons -SuccessfulLogons $successfulLogons

    # Summary table of top failed login sources
    if ($failedLogons.Count -gt 0) {
        Write-Log "--- Top Failed Login Sources ---" -Level INFO
        $failedLogons |
            Where-Object { $_.SourceIP -and $_.SourceIP -ne '-' } |
            Group-Object SourceIP |
            Sort-Object Count -Descending |
            Select-Object -First 10 |
            ForEach-Object {
                Write-Log ("  {0,15} : {1} failures" -f $_.Name, $_.Count) -Level INFO
            }
    }
}

# --- Entry Point ---

if (-not (Test-AdminPrivilege)) {
    Write-Warning "Administrator privileges recommended for full Security log access. Some events may be missing."
}

Write-Log "=== CyberPath Security Event Monitor Started ===" -Level INFO
Write-Log "Settings: Threshold=$FailureThreshold failures, Window=$TimeWindowMinutes min, Log=$LogPath" -Level INFO

if ($Continuous) {
    Write-Log "Running in continuous mode. Press Ctrl+C to stop." -Level INFO
    while ($true) {
        try {
            Invoke-SecurityEventScan
        } catch {
            Write-Log "Error during scan cycle: $_" -Level ERROR
        }
        Write-Log "Next scan in $WatchIntervalSeconds seconds..." -Level INFO
        Start-Sleep -Seconds $WatchIntervalSeconds
    }
} else {
    Invoke-SecurityEventScan
    Write-Log "=== Scan Complete ===" -Level INFO
}

#endregion
