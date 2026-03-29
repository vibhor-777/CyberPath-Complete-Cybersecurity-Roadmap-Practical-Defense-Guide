<#
.SYNOPSIS
    Configures PowerShell Script Block Logging and Transcription for auditability.

.DESCRIPTION
    Implements the following hardening measures via Group Policy registry keys:
    - PowerShell Script Block Logging (captures full script content, including deobfuscated code)
    - PowerShell Module Logging (logs pipeline execution details)
    - PowerShell Transcription (saves all session I/O to text files)
    These settings ensure all administrative PowerShell activity is recorded and
    difficult to obfuscate, supporting incident response and forensic analysis.

.PARAMETER TranscriptPath
    Directory where transcription logs will be written. Default: C:\PSTranscripts

.PARAMETER DisableLogging
    If specified, disables all PowerShell logging (use for rollback only).

.EXAMPLE
    # Enable all PowerShell logging with default transcript path
    .\Set-AuditLogging.ps1

.EXAMPLE
    # Enable with custom transcript path
    .\Set-AuditLogging.ps1 -TranscriptPath "D:\SecurityLogs\PSTranscripts"

.NOTES
    Author: CyberPath Defense Toolkit
    Requires: Administrator privileges (writes to HKLM)
    These settings apply machine-wide to all PowerShell sessions.
    Settings survive reboots.
    Reference: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$TranscriptPath  = 'C:\PSTranscripts',
    [switch]$DisableLogging
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-AdminPrivilege {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Write-Status {
    param([string]$Message, [string]$Status = 'OK')
    $color = switch ($Status) {
        'OK'   { 'Green' }
        'WARN' { 'Yellow' }
        'ERR'  { 'Red' }
        default { 'Cyan' }
    }
    Write-Host "  [$Status] $Message" -ForegroundColor $color
}

function Set-RegistryValue {
    param(
        [string]$Path,
        [string]$Name,
        $Value,
        [string]$Type = 'DWORD'
    )
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
}

# --- Entry Point ---

if (-not (Test-AdminPrivilege)) {
    Write-Error "This script requires Administrator privileges. Please re-run as Administrator."
    exit 1
}

$psRegBase = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'

if ($DisableLogging) {
    Write-Host "`n[INFO] Disabling PowerShell logging..." -ForegroundColor Yellow

    $paths = @(
        "$psRegBase\ScriptBlockLogging",
        "$psRegBase\ModuleLogging",
        "$psRegBase\Transcription"
    )
    foreach ($path in $paths) {
        if (Test-Path $path) {
            Remove-Item -Path $path -Recurse -Force
            Write-Status "Removed $path" -Status 'OK'
        }
    }
    Write-Host "`n[DONE] PowerShell logging disabled.`n" -ForegroundColor Yellow
    return
}

Write-Host "`n=== CyberPath: Configuring PowerShell Audit Logging ===" -ForegroundColor Cyan
Write-Host "Computer: $env:COMPUTERNAME | Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n"

# --- 1. Script Block Logging ---
# Captures the full content of every script block before execution.
# Critical: Even obfuscated/encoded scripts are logged AFTER deobfuscation.
Write-Host "[1/3] Configuring Script Block Logging..."
$sbPath = "$psRegBase\ScriptBlockLogging"

if ($PSCmdlet.ShouldProcess($sbPath, 'Enable Script Block Logging')) {
    Set-RegistryValue -Path $sbPath -Name 'EnableScriptBlockLogging'            -Value 1
    Set-RegistryValue -Path $sbPath -Name 'EnableScriptBlockInvocationLogging'  -Value 1
    Write-Status "Script Block Logging:            ENABLED (Event ID 4104)"
    Write-Status "Script Block Invocation Logging: ENABLED (Event IDs 4105/4106)"
}

# --- 2. Module Logging ---
# Captures pipeline execution details for all PowerShell modules.
Write-Host "`n[2/3] Configuring Module Logging..."
$mlPath     = "$psRegBase\ModuleLogging"
$mlModPath  = "$mlPath\ModuleNames"

if ($PSCmdlet.ShouldProcess($mlPath, 'Enable Module Logging')) {
    Set-RegistryValue -Path $mlPath -Name 'EnableModuleLogging' -Value 1

    # Log all modules (wildcard *)
    if (-not (Test-Path $mlModPath)) {
        New-Item -Path $mlModPath -Force | Out-Null
    }
    Set-ItemProperty -Path $mlModPath -Name '*' -Value '*' -Type String -Force
    Write-Status "Module Logging: ENABLED for all modules (wildcard *) (Event ID 4103)"
}

# --- 3. Transcription ---
# Saves a complete record of all input and output for every PowerShell session.
Write-Host "`n[3/3] Configuring Transcription..."
$tPath = "$psRegBase\Transcription"

# Create transcript directory with restricted permissions
if (-not (Test-Path $TranscriptPath)) {
    try {
        New-Item -ItemType Directory -Path $TranscriptPath -Force | Out-Null

        # Set DACL: SYSTEM and Administrators have full control; Users have write-only (append)
        $acl = Get-Acl -Path $TranscriptPath
        $acl.SetAccessRuleProtection($true, $false)  # Disable inheritance

        $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            'SYSTEM', 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'
        )
        $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            'Administrators', 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'
        )
        # Users can write (append transcripts) but cannot read or delete them
        $userRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            'Users', 'AppendData,CreateFiles', 'ContainerInherit,ObjectInherit', 'None', 'Allow'
        )

        $acl.AddAccessRule($systemRule)
        $acl.AddAccessRule($adminRule)
        $acl.AddAccessRule($userRule)
        Set-Acl -Path $TranscriptPath -AclObject $acl
        Write-Status "Transcript directory created: $TranscriptPath"
        Write-Status "Permissions: SYSTEM+Admins=FullControl, Users=AppendOnly"
    } catch {
        Write-Status "Failed to set transcript directory permissions: $_" -Status 'WARN'
    }
} else {
    Write-Status "Transcript directory already exists: $TranscriptPath"
}

if ($PSCmdlet.ShouldProcess($tPath, 'Enable Transcription')) {
    Set-RegistryValue -Path $tPath -Name 'EnableTranscripting'       -Value 1
    Set-RegistryValue -Path $tPath -Name 'EnableInvocationHeader'    -Value 1
    Set-RegistryValue -Path $tPath -Name 'OutputDirectory'           -Value $TranscriptPath -Type 'String'
    Write-Status "Transcription:         ENABLED"
    Write-Status "Invocation Headers:    ENABLED"
    Write-Status "Output Directory:      $TranscriptPath"
}

# --- Summary ---
Write-Host "`n=== Configuration Summary ===" -ForegroundColor Cyan
Write-Host "  Script Block Logging  : ENABLED  → Windows Event Log: Microsoft-Windows-PowerShell/Operational (Event IDs 4103-4106)"
Write-Host "  Module Logging        : ENABLED  → All modules logged"
Write-Host "  Transcription         : ENABLED  → Output: $TranscriptPath"
Write-Host ""
Write-Host "To verify, run in a NEW PowerShell session:" -ForegroundColor Yellow
Write-Host "  Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'" -ForegroundColor Gray
Write-Host "  Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -MaxEvents 10" -ForegroundColor Gray
Write-Host ""
Write-Host "Transcripts will be created in subdirectories under: $TranscriptPath" -ForegroundColor Green
Write-Host "Each session generates: PowerShell_transcript.[hostname].[random].[timestamp].txt" -ForegroundColor Green
Write-Host "`n=== Complete ===" -ForegroundColor Cyan
