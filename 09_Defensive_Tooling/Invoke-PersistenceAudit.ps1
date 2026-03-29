<#
.SYNOPSIS
    Persistence and Service Auditor — Inventories known persistence locations and flags anomalies.

.DESCRIPTION
    Audits the following Windows persistence mechanisms:
    - Registry Run keys (HKLM and HKCU)
    - Scheduled Tasks (non-Microsoft)
    - Installed Services (flagging random/suspicious names)
    - Startup folder items
    Compares results against a saved baseline to detect new or modified entries.

.PARAMETER BaselinePath
    Path to store/read the persistence baseline JSON file. Default: .\persistence_baseline.json

.PARAMETER SaveBaseline
    If specified, saves the current state as the new baseline (overwriting any existing baseline).

.PARAMETER Export
    If specified, exports the full audit report as a CSV file.

.PARAMETER ExportPath
    Path for the CSV export. Default: .\persistence_audit_[timestamp].csv

.EXAMPLE
    # Save initial baseline
    .\Invoke-PersistenceAudit.ps1 -SaveBaseline

.EXAMPLE
    # Audit and compare against baseline
    .\Invoke-PersistenceAudit.ps1

.EXAMPLE
    # Audit and export results to CSV
    .\Invoke-PersistenceAudit.ps1 -Export

.NOTES
    Author: CyberPath Defense Toolkit
    Requires: Administrator privileges for HKLM registry and service enumeration
#>

[CmdletBinding()]
param(
    [string]$BaselinePath  = ".\persistence_baseline.json",
    [switch]$SaveBaseline,
    [switch]$Export,
    [string]$ExportPath    = ".\persistence_audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

#region --- Constants ---

# Registry paths to audit for persistence
$REGISTRY_PERSISTENCE_PATHS = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',   # Userinit, Shell values
    'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute',
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
)

# Service name patterns that suggest randomness (indicators of malware)
$SUSPICIOUS_SERVICE_PATTERNS = @(
    '^[a-z0-9]{8,16}$',            # All lowercase alphanumeric, 8-16 chars (random-looking)
    '[0-9]{4,}',                    # 4+ consecutive digits
    '(svc|srv|service)\d{3,}',     # Generic service name + many numbers
    '^[A-Z][a-z][A-Z][a-z]'        # Alternating case (obfuscation)
)

# Trusted startup folder items (example — customize for your environment)
$TRUSTED_STARTUP_ITEMS = @(
    'Microsoft Teams',
    'OneDrive',
    'Slack'
)

#endregion

#region --- Collection Functions ---

function Get-RegistryPersistence {
    <#
    .SYNOPSIS Collects all values from known registry persistence locations.#>
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($path in $REGISTRY_PERSISTENCE_PATHS) {
        try {
            if (-not (Test-Path $path)) { continue }

            $item = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
            if (-not $item) { continue }

            # Get all properties except PS* built-ins
            $item.PSObject.Properties |
                Where-Object { $_.Name -notmatch '^PS' } |
                ForEach-Object {
                    $results.Add([PSCustomObject]@{
                        Type     = 'Registry'
                        Location = $path
                        Name     = $_.Name
                        Value    = $_.Value
                        Hash     = (Get-StringHash ($path + $_.Name + $_.Value))
                        Flagged  = $false
                        Reason   = ''
                    })
                }
        } catch {
            Write-Warning "Could not read registry path $path : $_"
        }
    }
    return $results
}

function Get-ScheduledTaskPersistence {
    <#
    .SYNOPSIS Enumerates non-Microsoft scheduled tasks that may indicate persistence.#>
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    try {
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue |
            Where-Object { $_.TaskPath -notlike '\Microsoft\*' -and $_.State -ne 'Disabled' }

        foreach ($task in $tasks) {
            $action = ($task.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join '; '
            $trigger = ($task.Triggers | ForEach-Object { $_.CimClass.CimClassName }) -join ', '

            # Flag tasks running from suspicious locations
            $isSuspicious = $action -match '\\Temp\\|\\AppData\\|\\ProgramData\\' -or
                            $action -match 'powershell.*-enc|-e\s+[A-Za-z0-9+/=]{20,}' -or
                            $action -match 'wscript|mshta|regsvr32.*http|rundll32.*http'

            $results.Add([PSCustomObject]@{
                Type     = 'ScheduledTask'
                Location = $task.TaskPath
                Name     = $task.TaskName
                Value    = $action
                Hash     = (Get-StringHash ($task.TaskPath + $task.TaskName + $action))
                Flagged  = $isSuspicious
                Reason   = if ($isSuspicious) { 'Executes from temp/appdata or uses obfuscated command' } else { '' }
            })
        }
    } catch {
        Write-Warning "Error enumerating scheduled tasks: $_"
    }
    return $results
}

function Get-ServicePersistence {
    <#
    .SYNOPSIS Enumerates installed services and flags those with suspicious characteristics.#>
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    try {
        $services = Get-WmiObject Win32_Service -ErrorAction SilentlyContinue |
            Where-Object { $_.StartMode -ne 'Disabled' }

        foreach ($svc in $services) {
            # Check service name against suspicious patterns
            $isSuspicious = $false
            $reason = ''

            foreach ($pattern in $SUSPICIOUS_SERVICE_PATTERNS) {
                if ($svc.Name -match $pattern) {
                    $isSuspicious = $true
                    $reason += "Name matches suspicious pattern '$pattern'. "
                    break
                }
            }

            # Flag services running from temp or user profile directories
            if ($svc.PathName -match '\\Temp\\|\\AppData\\|\\ProgramData\\[^\\]+\\[a-z0-9]{8,16}') {
                $isSuspicious = $true
                $reason += "Runs from suspicious path. "
            }

            $results.Add([PSCustomObject]@{
                Type     = 'Service'
                Location = "HKLM:\SYSTEM\CurrentControlSet\Services\$($svc.Name)"
                Name     = $svc.Name
                Value    = "$($svc.DisplayName) | Path: $($svc.PathName) | State: $($svc.State)"
                Hash     = (Get-StringHash ($svc.Name + $svc.PathName))
                Flagged  = $isSuspicious
                Reason   = $reason.Trim()
            })
        }
    } catch {
        Write-Warning "Error enumerating services: $_"
    }
    return $results
}

function Get-StartupFolderPersistence {
    <#
    .SYNOPSIS Enumerates items in Windows startup folders.#>
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    $startupPaths = @(
        [System.Environment]::GetFolderPath('Startup'),
        [System.Environment]::GetFolderPath('CommonStartup')
    )

    foreach ($startupPath in $startupPaths) {
        if (-not (Test-Path $startupPath)) { continue }

        Get-ChildItem -Path $startupPath -ErrorAction SilentlyContinue | ForEach-Object {
            $isTrusted = $TRUSTED_STARTUP_ITEMS | Where-Object { $_.Name -like "*$_*" }
            $results.Add([PSCustomObject]@{
                Type     = 'StartupFolder'
                Location = $startupPath
                Name     = $_.Name
                Value    = $_.FullName
                Hash     = (Get-StringHash ($startupPath + $_.Name))
                Flagged  = -not [bool]$isTrusted
                Reason   = if (-not $isTrusted) { 'Not in trusted startup items list' } else { '' }
            })
        }
    }
    return $results
}

function Get-StringHash {
    <#
    .SYNOPSIS Generates a short SHA-256 hash of a string for change detection.#>
    param([string]$InputString)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($InputString)
    $sha   = [System.Security.Cryptography.SHA256]::Create()
    $hash  = $sha.ComputeHash($bytes)
    return ([BitConverter]::ToString($hash) -replace '-','').Substring(0,16)
}

#endregion

#region --- Baseline and Comparison ---

function Save-Baseline {
    param([array]$CurrentState)
    $baseline = @{
        CreatedAt    = (Get-Date -Format 'o')
        ComputerName = $env:COMPUTERNAME
        Items        = $CurrentState
    }
    $baseline | ConvertTo-Json -Depth 10 | Set-Content -Path $BaselinePath -Encoding UTF8
    Write-Host "[INFO] Baseline saved to $BaselinePath ($($CurrentState.Count) items)" -ForegroundColor Green
}

function Compare-WithBaseline {
    param(
        [array]$CurrentState,
        [string]$BaselinePath
    )

    if (-not (Test-Path $BaselinePath)) {
        Write-Host "[WARN] No baseline found at $BaselinePath. Run with -SaveBaseline first." -ForegroundColor Yellow
        return
    }

    $baseline = Get-Content -Path $BaselinePath -Raw | ConvertFrom-Json
    Write-Host "`n[INFO] Comparing against baseline from $($baseline.CreatedAt)" -ForegroundColor Cyan

    $baselineHashes = $baseline.Items | ForEach-Object { $_.Hash }
    $currentHashes  = $CurrentState   | ForEach-Object { $_.Hash }

    # New items not in baseline
    $newItems = $CurrentState | Where-Object { $_.Hash -notin $baselineHashes }
    # Removed items no longer present
    $removedItems = $baseline.Items | Where-Object { $_.Hash -notin $currentHashes }

    if ($newItems.Count -gt 0) {
        Write-Host "`n[ALERT] $($newItems.Count) NEW persistence item(s) detected since baseline:" -ForegroundColor Red
        $newItems | ForEach-Object {
            Write-Host "  [NEW] Type=$($_.Type) | Location=$($_.Location) | Name=$($_.Name)" -ForegroundColor Red
            Write-Host "        Value=$($_.Value)" -ForegroundColor Red
        }
    } else {
        Write-Host "[OK] No new persistence items since baseline." -ForegroundColor Green
    }

    if ($removedItems.Count -gt 0) {
        Write-Host "`n[INFO] $($removedItems.Count) item(s) removed since baseline:" -ForegroundColor Yellow
        $removedItems | ForEach-Object {
            Write-Host "  [REMOVED] Type=$($_.Type) | Name=$($_.Name)" -ForegroundColor Yellow
        }
    }
}

#endregion

#region --- Main ---

Write-Host "=== CyberPath Persistence Auditor ===" -ForegroundColor Cyan
Write-Host "Computer: $env:COMPUTERNAME | User: $env:USERNAME | Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n"

# Collect all persistence items
Write-Host "[*] Collecting registry persistence..." -ForegroundColor Gray
$registryItems = Get-RegistryPersistence

Write-Host "[*] Collecting scheduled tasks..." -ForegroundColor Gray
$taskItems = Get-ScheduledTaskPersistence

Write-Host "[*] Collecting services..." -ForegroundColor Gray
$serviceItems = Get-ServicePersistence

Write-Host "[*] Collecting startup folder items..." -ForegroundColor Gray
$startupItems = Get-StartupFolderPersistence

$allItems = @($registryItems) + @($taskItems) + @($serviceItems) + @($startupItems)

# Report flagged items
$flagged = $allItems | Where-Object { $_.Flagged }
if ($flagged.Count -gt 0) {
    Write-Host "`n[ALERT] $($flagged.Count) SUSPICIOUS persistence item(s) found:" -ForegroundColor Red
    $flagged | ForEach-Object {
        Write-Host "  [!] [$($_.Type)] $($_.Name)" -ForegroundColor Red
        Write-Host "      Location : $($_.Location)" -ForegroundColor Red
        Write-Host "      Value    : $($_.Value)" -ForegroundColor Red
        Write-Host "      Reason   : $($_.Reason)" -ForegroundColor Yellow
        Write-Host ""
    }
} else {
    Write-Host "[OK] No immediately suspicious persistence items flagged." -ForegroundColor Green
}

Write-Host "`n[INFO] Total items found: Registry=$($registryItems.Count) | Tasks=$($taskItems.Count) | Services=$($serviceItems.Count) | Startup=$($startupItems.Count)"

# Baseline operations
if ($SaveBaseline) {
    Save-Baseline -CurrentState $allItems
} else {
    Compare-WithBaseline -CurrentState $allItems -BaselinePath $BaselinePath
}

# Export
if ($Export) {
    $allItems | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
    Write-Host "`n[INFO] Full audit exported to: $ExportPath" -ForegroundColor Cyan
}

Write-Host "`n=== Audit Complete ===" -ForegroundColor Cyan

#endregion
