# Linux Hardening

> **Module:** 03 — System Security | **Focus:** Defensive configuration of Linux endpoints and servers

Linux underpins the majority of the internet's infrastructure — web servers, cloud workloads, containerised applications, and critical back-end systems. Despite a reputation for being more secure than Windows out of the box, a default Linux installation leaves significant attack surface exposed. This guide covers the essential hardening controls every defender must apply, aligned with the CIS Benchmark for Linux.

---

## 📋 Table of Contents

1. [User and Group Management](#1-user-and-group-management)
2. [File Permissions and Sticky Bits](#2-file-permissions-and-sticky-bits)
3. [SSH Hardening](#3-ssh-hardening)
4. [sudo Configuration and /etc/sudoers](#4-sudo-configuration-and-etcsudoers)
5. [auditd for System Logging](#5-auditd-for-system-logging)
6. [Firewall with iptables and ufw](#6-firewall-with-iptables-and-ufw)
7. [Disabling Unnecessary Services](#7-disabling-unnecessary-services)
8. [CIS Benchmark Alignment](#8-cis-benchmark-alignment)
9. [Module Practice Challenge](#9-module-practice-challenge)

---

## 1. User and Group Management

### 🟢 Beginner Explanation

On Linux, every action is performed in the context of a user account. The operating system uses users and groups to control who can access what. A well-managed system has the minimum number of user accounts, with only the permissions they need to perform their job — nothing more. This is the **principle of least privilege** in practice.

The two files that store user information are:
- `/etc/passwd` — stores account information (username, UID, home directory, shell)
- `/etc/shadow` — stores hashed passwords (readable only by root)

### 🔬 Technical Deep Dive

#### Anatomy of /etc/passwd

Each line in `/etc/passwd` follows this format:

```
username:x:UID:GID:GECOS:home_directory:login_shell
```

```bash
# View /etc/passwd
cat /etc/passwd

# Example entry:
# alice:x:1001:1001:Alice Smith,,,:/home/alice:/bin/bash
# daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
#
# The 'x' in field 2 means the password is stored in /etc/shadow
# /usr/sbin/nologin = service account that cannot log in interactively
```

#### Anatomy of /etc/shadow

```bash
# View /etc/shadow (requires root)
sudo cat /etc/shadow

# Format: username:$algo$salt$hash:lastchange:min:max:warn:inactive:expire:reserved
# Example:
# alice:$6$randomsalt$hashedpassword...:19500:0:99999:7:::
#
# $6$ = SHA-512 (preferred)
# $5$ = SHA-256
# $1$ = MD5 (insecure — should not appear)
# lastchange = days since epoch of last password change
```

#### Creating and Managing Users

```bash
# Create a new standard user with a home directory
sudo adduser alice
# adduser is the high-level, interactive command (Debian/Ubuntu)
# useradd is the lower-level command — requires manual home dir creation

# Create a system/service account (no home dir, no login shell)
sudo useradd --system --no-create-home --shell /usr/sbin/nologin serviceaccount

# Modify an existing user
sudo usermod --shell /bin/bash alice          # Change login shell
sudo usermod --home /new/home --move-home alice  # Move home directory
sudo usermod --lock alice                    # Lock account (prepends ! to hash)
sudo usermod --unlock alice                  # Unlock account
sudo usermod --expiredate 2024-12-31 alice   # Set account expiry

# Add user to a group (e.g., sudo group)
sudo usermod --append --groups sudo alice
# Or using adduser (preferred on Debian/Ubuntu)
sudo adduser alice sudo

# Delete a user and their home directory
# ⚠️ Lab Environment Only — irreversible without backup
sudo deluser --remove-home alice
```

#### Auditing User Accounts

```bash
# List all accounts with interactive shells (potential human accounts)
grep -v '/usr/sbin/nologin\|/bin/false\|/sbin/nologin' /etc/passwd |
    awk -F: '{print $1, $3, $7}'

# Find accounts with UID 0 (root-equivalent) — should only be 'root'
awk -F: '($3 == 0)' /etc/passwd

# Find accounts with empty passwords (critical security risk)
sudo awk -F: '($2 == "" || $2 == "!!" )' /etc/shadow

# Find accounts that have never logged in
sudo lastlog | grep "Never logged in"

# List all groups and their members
cat /etc/group

# Find users in the sudo / wheel group
grep -E '^sudo|^wheel' /etc/group

# Check which users have valid shells
cat /etc/shells                          # Authorised shells
grep -v '/nologin\|/false' /etc/passwd  # Accounts with real shells
```

#### Password Quality Enforcement with PAM

Install and configure `libpam-pwquality` (Debian/Ubuntu) or `pam_pwquality` (RHEL/CentOS):

```bash
# Install on Debian/Ubuntu
sudo apt-get install libpam-pwquality -y

# Edit /etc/security/pwquality.conf
sudo nano /etc/security/pwquality.conf
```

```ini
# /etc/security/pwquality.conf — recommended settings
minlen  = 14          # Minimum password length
dcredit = -1          # Require at least 1 digit
ucredit = -1          # Require at least 1 uppercase letter
lcredit = -1          # Require at least 1 lowercase letter
ocredit = -1          # Require at least 1 special character
maxrepeat = 3         # Maximum consecutive identical characters
gecoscheck = 1        # Check against GECOS (full name) field
dictcheck = 1         # Check against dictionary words
```

#### Configuring Password Ageing with chage

```bash
# View current password ageing for a user
sudo chage --list alice

# Set password ageing policy
sudo chage --maxdays 365 alice      # Force password change every 365 days
sudo chage --mindays 1 alice        # Minimum 1 day before password can be changed again
sudo chage --warndays 14 alice      # Warn 14 days before expiry
sudo chage --inactive 30 alice      # Lock account 30 days after password expiry

# Force password change on next login
sudo chage --lastday 0 alice

# Set global defaults in /etc/login.defs
sudo grep -E 'PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE' /etc/login.defs
```

```bash
# /etc/login.defs — relevant password ageing settings
# PASS_MAX_DAYS   365
# PASS_MIN_DAYS   1
# PASS_WARN_AGE   14
# LOGIN_RETRIES   5
# LOGIN_TIMEOUT   60
```

### 🌍 Real-World Relevance

In cloud environments, default Linux images frequently ship with the `ubuntu`, `ec2-user`, or `centos` accounts configured with overly broad SSH key access. Numerous cloud breaches have resulted from developers leaving default credentials intact or sharing SSH keys across teams. The 2019 Capital One breach involved an SSRF vulnerability exploited against an IAM role on an EC2 instance — user privilege management is equally critical in cloud workloads.

### 🛡️ Defensive Measures

- Audit `/etc/passwd` monthly for accounts with unexpected shells or UIDs
- Remove or lock all accounts for departed employees immediately
- Service accounts must use `/usr/sbin/nologin` as their shell
- Enforce password complexity via PAM and `pwquality.conf`
- Monitor `/etc/passwd` and `/etc/shadow` for changes using auditd (Section 5)

---

## 2. File Permissions and Sticky Bits

### 🟢 Beginner Explanation

In Linux, every file and directory has an owner (a user) and a group, and three sets of permissions: one for the owner, one for the group, and one for everyone else. Permissions control whether someone can **read (r)**, **write (w)**, or **execute (x)** a file. Incorrect permissions are one of the most common causes of privilege escalation on Linux systems.

Special permission bits — **setuid**, **setgid**, and the **sticky bit** — add additional nuance that defenders must understand.

### 🔬 Technical Deep Dive

#### Understanding Octal Permissions

```
Permission  Octal  Meaning
---------   -----  -------
---         0      No permissions
--x         1      Execute only
-w-         2      Write only
-wx         3      Write + Execute
r--         4      Read only
r-x         5      Read + Execute
rw-         6      Read + Write
rwx         7      Read + Write + Execute

Full format: owner | group | others
Example: 755 = rwxr-xr-x
         640 = rw-r-----
         600 = rw-------
```

```bash
# View file permissions in long format
ls -la /etc/passwd
ls -la /etc/shadow

# Expected permissions:
# -rw-r--r-- 1 root root  /etc/passwd     (644)
# -rw-r----- 1 root shadow /etc/shadow    (640)
# -rw------- 1 root root  /etc/sudoers   (440)
```

#### chmod — Changing Permissions

```bash
# Set permissions using octal notation
chmod 644 /path/to/file    # rw-r--r--
chmod 600 ~/.ssh/id_rsa    # rw------- (SSH private key — critical)
chmod 700 ~/.ssh           # rwx------ (SSH directory)
chmod 755 /path/to/dir     # rwxr-xr-x (public directory)

# Set permissions using symbolic notation
chmod u+x script.sh        # Add execute for owner
chmod g-w file.txt         # Remove write for group
chmod o-rwx sensitive.txt  # Remove all permissions for others
chmod a+r public.txt       # Add read for all (owner, group, others)

# Apply recursively (use with caution)
# ⚠️ Lab Environment Only — recursive chmod on system directories can break the OS
chmod -R 750 /secure/directory
```

#### chown — Changing Ownership

```bash
# Change owner
sudo chown root /etc/crontab

# Change owner and group simultaneously
sudo chown root:root /etc/crontab

# Change only the group
sudo chown :www-data /var/www/html

# Recursive ownership change
# ⚠️ Lab Environment Only
sudo chown -R alice:developers /home/alice/project
```

#### Special Permission Bits

**Setuid (SUID) — bit value 4**
When set on an executable, it runs as the file's owner (often root), regardless of who executes it:

```bash
# Find all SUID binaries on the system
find / -perm -4000 -type f 2>/dev/null | sort

# Common legitimate SUID binaries:
# /usr/bin/sudo       — run commands as root
# /usr/bin/passwd     — change passwords (needs to write /etc/shadow)
# /usr/bin/ping       — raw socket access
# /usr/bin/su         — switch user

# Any unexpected SUID binary is a red flag — investigate immediately
# Example of a SUID shell (attacker left behind as backdoor):
# -rwsr-xr-x root root /tmp/bash   ← CRITICAL — should not exist

# Remove SUID from a file if not needed
# ⚠️ Lab Environment Only — removing SUID from system binaries can break functionality
sudo chmod u-s /path/to/suspicious_binary
```

**Setgid (SGID) — bit value 2**
On a file: runs as the file's group. On a directory: new files inherit the directory's group:

```bash
# Find all SGID binaries
find / -perm -2000 -type f 2>/dev/null | sort

# Set SGID on a shared directory so all files inherit the group
sudo chmod g+s /shared/project
```

**Sticky Bit — bit value 1**
On a directory, prevents users from deleting or renaming files they do not own, even if they have write permission on the directory. This is set on `/tmp` by default:

```bash
# View sticky bit (shown as 't' in the execute position for others)
ls -ld /tmp
# drwxrwxrwt 20 root root 4096 Jan  1 12:00 /tmp
#          ^--- 't' = sticky bit set

# Set sticky bit on a shared directory
sudo chmod +t /shared/uploads

# The sticky bit on /tmp is critical — without it, any user could delete other
# users' temporary files, causing denial of service or data loss
```

#### World-Writable File Audit

```bash
# Find all world-writable files (excludes /proc and /sys)
find / -path /proc -prune -o -path /sys -prune -o \
    -perm -0002 -type f -print 2>/dev/null

# Find world-writable directories (more dangerous — attackers can plant files)
find / -path /proc -prune -o -path /sys -prune -o \
    -perm -0002 -type d -print 2>/dev/null

# Find files with no owner (orphaned — potentially left by deleted users)
find / -nouser -o -nogroup 2>/dev/null | grep -v '/proc\|/sys'
```

#### Critical File Permission Baseline

```bash
# Verify critical file permissions
check_perm() {
    local file="$1"
    local expected="$2"
    local actual
    actual=$(stat -c "%a" "$file" 2>/dev/null)
    if [ "$actual" != "$expected" ]; then
        echo "⚠ MISMATCH: $file — expected $expected, found $actual"
    else
        echo "✓ OK: $file ($actual)"
    fi
}

check_perm /etc/passwd        644
check_perm /etc/shadow        640
check_perm /etc/group         644
check_perm /etc/gshadow       640
check_perm /etc/crontab       600
check_perm /etc/ssh/sshd_config 600
check_perm /boot/grub/grub.cfg 700
```

### 🌍 Real-World Relevance

Misconfigured SUID binaries are one of the most common local privilege escalation vectors on Linux systems. GTFOBins (gtfobins.github.io) is a public reference documenting over 200 SUID binaries that can be abused to escalate privileges. Pentesters and attackers routinely check `find / -perm -4000` as one of their first post-exploitation steps on a compromised Linux host.

### 🛡️ Defensive Measures

- Run SUID/SGID audits monthly and maintain an approved whitelist
- Use `umask 027` in `/etc/profile` and `/etc/bash.bashrc` to restrict default file creation permissions
- Mount `/tmp`, `/var/tmp`, and `/home` with `noexec,nosuid` options in `/etc/fstab`
- Alert using auditd (Section 5) on changes to SUID binaries

---

## 3. SSH Hardening

### 🟢 Beginner Explanation

SSH (Secure Shell) is the primary remote access method for Linux systems. By default, SSH is reasonably secure — it uses encrypted communication — but its default configuration makes several concessions to compatibility that a hardened system should eliminate. Improperly configured SSH is one of the top vectors for unauthorised access to Linux servers.

### 🔬 Technical Deep Dive

#### The SSH Configuration File

The main SSH daemon configuration is at `/etc/ssh/sshd_config`. After any change, reload the daemon:

```bash
# Test configuration syntax before reloading
sudo sshd -t

# Reload SSH daemon (apply changes without dropping existing connections)
sudo systemctl reload sshd

# View current effective SSH configuration
sudo sshd -T
```

#### Complete Hardened sshd_config

```bash
# /etc/ssh/sshd_config — Hardened configuration
# ⚠️ Lab Environment Only — apply incrementally; a misconfiguration can lock you out
# Always keep an active root console session open when modifying sshd_config
```

```ini
# --- Protocol and Port ---
Port 22                          # Consider changing to a non-standard port in high-risk environments
Protocol 2                       # SSHv1 is broken — never use it
AddressFamily inet               # IPv4 only (change to 'any' if IPv6 is needed)

# --- Host Keys ---
HostKey /etc/ssh/ssh_host_ed25519_key    # Preferred — Ed25519 is modern and fast
HostKey /etc/ssh/ssh_host_rsa_key        # RSA fallback for compatibility

# --- Ciphers and Key Exchange ---
# Remove weak ciphers — use only strong, modern algorithms
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com
KexAlgorithms curve25519-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512

# --- Authentication ---
PermitRootLogin no               # Never allow direct root SSH
PasswordAuthentication no        # Disable password auth — require keys
PubkeyAuthentication yes         # Enable public key authentication
AuthorizedKeysFile .ssh/authorized_keys  # Standard location for authorized keys
PermitEmptyPasswords no          # Never permit empty passwords
ChallengeResponseAuthentication no
UsePAM yes

# --- MFA (optional but recommended for privileged access) ---
# AuthenticationMethods publickey,keyboard-interactive

# --- Session Hardening ---
MaxAuthTries 3                   # Maximum failed authentication attempts
MaxSessions 10                   # Maximum concurrent sessions per connection
LoginGraceTime 30                # Seconds to authenticate before disconnecting
ClientAliveInterval 300          # Send keepalive every 5 minutes
ClientAliveCountMax 2            # Disconnect after 2 missed keepalives (10 min idle)
TCPKeepAlive no                  # Prefer ClientAlive over TCP-level keepalive

# --- Access Control ---
AllowUsers alice bob             # Whitelist specific users (comment out if using AllowGroups)
# AllowGroups sshusers           # Alternative: only allow specific group
DenyUsers root administrator     # Explicitly deny high-value account names
# AllowUsers *@192.168.1.0/24   # Restrict user to specific source network

# --- Feature Restrictions ---
X11Forwarding no                 # Disable X11 forwarding (rarely needed, increases attack surface)
AllowTcpForwarding no            # Disable TCP tunnelling (unless required)
AllowAgentForwarding no          # Disable SSH agent forwarding (prevents credential forwarding)
GatewayPorts no                  # Prevent remote hosts from connecting to forwarded ports
PermitTunnel no                  # Disable VPN tunnelling over SSH
PrintMotd no                     # Control MOTD display

# --- Logging ---
SyslogFacility AUTH
LogLevel VERBOSE                 # Log more detail — capture fingerprints of connecting keys

# --- SFTP Subsystem ---
Subsystem sftp /usr/lib/openssh/sftp-server
```

#### Generating Strong SSH Keys

```bash
# Generate an Ed25519 key pair (preferred — modern, compact, fast)
ssh-keygen -t ed25519 -C "alice@company.com" -f ~/.ssh/id_ed25519

# Generate RSA key (if Ed25519 not supported by target)
ssh-keygen -t rsa -b 4096 -C "alice@company.com" -f ~/.ssh/id_rsa

# Protect private key with a strong passphrase when prompted
# Never create keys without a passphrase for production use

# Set correct permissions on the key files
chmod 700 ~/.ssh
chmod 600 ~/.ssh/id_ed25519
chmod 644 ~/.ssh/id_ed25519.pub

# Install public key on remote server
ssh-copy-id -i ~/.ssh/id_ed25519.pub alice@server_ip

# Or manually append to authorized_keys
cat ~/.ssh/id_ed25519.pub | ssh alice@server_ip "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
```

#### SSH Key Management Best Practices

```bash
# Audit authorized_keys files across the system
find /home /root -name "authorized_keys" -exec ls -la {} \; 2>/dev/null
find /home /root -name "authorized_keys" -exec cat {} \; 2>/dev/null

# Check for keys with no passphrase restriction
# (look for entries without from= or command= restrictions in authorized_keys)
cat ~/.ssh/authorized_keys

# Restrict a key to specific commands only (useful for backup scripts)
# In authorized_keys:
# command="/usr/bin/rsync --server ...",no-port-forwarding,no-X11-forwarding,no-agent-forwarding ssh-ed25519 AAAA...

# Audit SSH connections currently active
who
w
last | head -20
lastb | head -20  # Failed logon attempts
```

#### Configuring SSH Fail2Ban

```bash
# Install fail2ban (Debian/Ubuntu)
sudo apt-get install fail2ban -y

# Create local jail configuration
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
```

```ini
# /etc/fail2ban/jail.local — SSH section
[sshd]
enabled  = true
port     = ssh
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 3
findtime = 300      # 5-minute window
bantime  = 3600     # Ban for 1 hour
```

```bash
# Start and enable fail2ban
sudo systemctl enable --now fail2ban

# Check banned IPs
sudo fail2ban-client status sshd

# Manually unban an IP
sudo fail2ban-client set sshd unbanip 192.168.1.100
```

### 🌍 Real-World Relevance

Shodan (the search engine for internet-connected devices) shows millions of SSH servers accessible on the public internet, many with password authentication enabled. Automated botnets continuously scan for and attempt to brute-force SSH logins — logs from exposed SSH servers commonly show thousands of failed attempts per day from hundreds of IP addresses. Disabling password authentication and enabling key-based auth eliminates this entire attack class.

### 🛡️ Defensive Measures

- Disable password authentication entirely — use only key-based auth
- Never permit root direct SSH login
- Use `AllowUsers` or `AllowGroups` to restrict which accounts can SSH
- Enable `fail2ban` or `sshguard` for automated brute-force protection
- Monitor `/var/log/auth.log` for repeated failed attempts (Event: Invalid user / authentication failure)
- Rotate SSH host keys annually and when staff leave

---

## 4. sudo Configuration and /etc/sudoers

### 🟢 Beginner Explanation

`sudo` ("superuser do") allows a normal user to run specific commands with elevated privileges, without giving them the root password. The `/etc/sudoers` file controls exactly which users can run which commands as which accounts — and it is one of the most security-critical files on the system. A misconfigured `sudoers` file is a frequent source of privilege escalation.

### 🔬 Technical Deep Dive

#### Safe Editing with visudo

**Never edit /etc/sudoers directly with a text editor.** Use `visudo`, which validates the syntax before saving and prevents configuration errors that could lock you out:

```bash
# Edit sudoers safely
sudo visudo

# Edit sudoers for a specific user's file in /etc/sudoers.d/
sudo visudo -f /etc/sudoers.d/alice
```

#### Anatomy of a sudoers Rule

```
WHO  WHERE=(AS_WHOM)  COMMAND
```

```bash
# /etc/sudoers — common patterns

# The root user can run any command from anywhere as anyone
root    ALL=(ALL:ALL) ALL

# Members of the sudo group can run any command
%sudo   ALL=(ALL:ALL) ALL

# Allow alice to run only specific commands as root
alice   ALL=(root) /usr/bin/apt, /usr/sbin/service, /bin/systemctl

# Allow the 'webadmin' group to restart nginx only, without a password prompt
%webadmin  ALL=(root) NOPASSWD: /bin/systemctl restart nginx

# Allow backup user to run rsync as root without password
backup  ALL=(root) NOPASSWD: /usr/bin/rsync

# Allow alice to run ALL commands as any user (avoid this pattern)
# alice  ALL=(ALL) ALL    ← This is equivalent to giving alice root

# Dangerous patterns to avoid:
# alice  ALL=(ALL) NOPASSWD: ALL              ← Root with no password
# alice  ALL=(ALL) /bin/bash                  ← Direct shell escalation
# alice  ALL=(ALL) /usr/bin/vim               ← vim can spawn a shell
# alice  ALL=(ALL) /usr/bin/find              ← find can exec commands
# alice  ALL=(ALL) /usr/bin/python3           ← python can spawn a shell
# alice  ALL=(ALL) /usr/bin/awk               ← awk can exec commands
```

#### Auditing sudo Usage

```bash
# View sudo log — all sudo commands are logged
# On systems using syslog:
grep sudo /var/log/auth.log | tail -50

# On systems using journald:
journalctl _COMM=sudo --no-pager | tail -50

# Find all sudoers files
sudo cat /etc/sudoers
sudo ls -la /etc/sudoers.d/
sudo cat /etc/sudoers.d/*

# Check what commands the current user can run with sudo
sudo -l

# Check what commands another user can run (requires root)
sudo -l -U alice
```

#### GTFOBins Awareness — Dangerous sudo Grants

The following binaries should **never** be granted via sudo without restrictions, because they can trivially spawn a root shell:

```bash
# If alice has: alice ALL=(root) /usr/bin/vim
# She can escalate with:
sudo vim -c ':!bash'     # Spawns root shell from within vim

# If alice has: alice ALL=(root) /usr/bin/find
sudo find / -name "x" -exec /bin/bash \;  # Executes bash as root

# If alice has: alice ALL=(root) /usr/bin/python3
sudo python3 -c "import pty; pty.spawn('/bin/bash')"

# Reference: https://gtfobins.github.io/
# Always check GTFOBins before adding any binary to sudoers
```

#### sudo Configuration Hardening

```bash
# /etc/sudoers — add these security-enhancing defaults

# Require TTY (prevents non-interactive sudo abuse)
Defaults    requiretty

# Log all sudo commands with input/output (detailed audit trail)
Defaults    log_input, log_output

# Secure path — prevents PATH manipulation attacks
Defaults    secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Set sudo password prompt timeout (0 = always require password)
Defaults    timestamp_timeout=0

# Set sudo authentication failure message
Defaults    badpass_message="Access denied."

# Authenticate with the invoking user's password, not the target user's
Defaults    rootpw   # ← Uncomment to require the root password instead

# Limit sudo to specific terminals
Defaults    lecture=always
```

### 🌍 Real-World Relevance

The GTFOBins project catalogues hundreds of binaries that can be exploited for privilege escalation via misconfigured sudo rules. In penetration testing engagements, `sudo -l` is one of the first commands run after gaining a shell — finding that a low-privilege user can run `vim`, `python`, or `find` as root is game over for that system. CIS Benchmark controls explicitly address sudo configuration to mitigate these risks.

### 🛡️ Defensive Measures

- Follow the principle of least privilege — grant specific commands, not `ALL`
- Never use `NOPASSWD: ALL`
- Audit sudoers weekly with `sudo cat /etc/sudoers && cat /etc/sudoers.d/*`
- Monitor sudo activity logs for unusual patterns
- Cross-reference every binary in sudoers rules against GTFOBins
- Use `/etc/sudoers.d/` for modular configuration management

---

## 5. auditd for System Logging

### 🟢 Beginner Explanation

`auditd` is the Linux kernel's audit subsystem. Unlike application-level logging, auditd hooks directly into the kernel and can record nearly any system call, file access, or user action — providing a tamper-resistant, detailed audit trail. It is the Linux equivalent of Windows Advanced Audit Policy + Sysmon combined.

### 🔬 Technical Deep Dive

#### Installing and Managing auditd

```bash
# Install auditd (Debian/Ubuntu)
sudo apt-get install auditd audispd-plugins -y

# Install on RHEL/CentOS
sudo yum install audit -y

# Enable and start
sudo systemctl enable --now auditd

# Check status
sudo systemctl status auditd
sudo auditctl -s    # Show audit daemon status and statistics
```

#### Audit Rules

Audit rules are defined in `/etc/audit/rules.d/` (persistent) or added temporarily with `auditctl`:

```bash
# /etc/audit/rules.d/hardening.rules

# --- Rule format ---
# -w <path>    : Watch a file or directory
# -p <perms>   : Permission filter: r=read, w=write, x=execute, a=attribute change
# -k <key>     : Tag for filtering in ausearch
# -a <list>,<action> -S <syscall> : Syscall rules

# Protect critical authentication and identity files
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Monitor sudoers changes
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# Monitor SSH configuration
-w /etc/ssh/sshd_config -p wa -k sshd_config

# Monitor cron and at jobs (persistence via scheduled tasks)
-w /etc/cron.allow -p wa -k cron
-w /etc/cron.deny -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.weekly/ -p wa -k cron
-w /etc/cron.monthly/ -p wa -k cron
-w /etc/crontab -p wa -k cron
-w /var/spool/cron/ -p wa -k cron
-w /etc/at.allow -p wa -k at
-w /etc/at.deny -p wa -k at

# Monitor PAM and authentication modules
-w /etc/pam.d/ -p wa -k pam
-w /etc/security/ -p wa -k security

# Kernel module loading (rootkit installation attempt)
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module,delete_module -k modules

# System call monitoring — privilege escalation
-a always,exit -F arch=b64 -S setuid -k setuid
-a always,exit -F arch=b64 -S setgid -k setgid
-a always,exit -F arch=b64 -S setreuid -k setuid
-a always,exit -F arch=b64 -S setregid -k setgid

# Executable creation/modification
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -k chmod
-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -k chown

# Failed access attempts — detect reconnaissance
-a always,exit -F arch=b64 -S open,openat,creat -F exit=-EACCES -k access
-a always,exit -F arch=b64 -S open,openat,creat -F exit=-EPERM -k access

# Suspicious process execution from world-writable directories
-a always,exit -F arch=b64 -S execve -F dir=/tmp -k suspicious_exec
-a always,exit -F arch=b64 -S execve -F dir=/var/tmp -k suspicious_exec

# Network configuration changes
-a always,exit -F arch=b64 -S sethostname,setdomainname -k network_config
-w /etc/hosts -p wa -k network_config
-w /etc/network/ -p wa -k network_config

# Immutable rule — make rules unchangeable without reboot
# -e 2   ← Uncomment in production after all rules are finalised
```

```bash
# Load rules from file
sudo augenrules --load

# List current active rules
sudo auditctl -l

# Temporarily add a watch rule
sudo auditctl -w /etc/passwd -p wa -k identity_temp
```

#### Querying Audit Logs

```bash
# Search audit logs by key tag
sudo ausearch -k identity --start today | aureport -f -i

# Search for all sudo activity
sudo ausearch -k sudoers --start today

# Generate a summary report of failed events
sudo aureport --failed --start today

# Find all file accesses that were denied
sudo ausearch -k access --start today

# List all commands run by a specific user
sudo ausearch -ua 1001 --start today | grep type=EXECVE

# Report on authentication activity
sudo aureport --auth --start today

# Raw event for a specific event ID
sudo ausearch -a 12345

# Watch audit log in real time
sudo tail -f /var/log/audit/audit.log | audisp-prelude
```

#### Protecting Audit Logs

```bash
# /etc/audit/auditd.conf — key settings
# max_log_file = 100          # Maximum log file size in MB
# num_logs = 10               # Number of rotated log files to keep
# max_log_file_action = ROTATE
# space_left = 500            # Alert when disk space drops below this (MB)
# space_left_action = SYSLOG
# admin_space_left = 50       # Action when critically low
# admin_space_left_action = HALT  # Stop system rather than lose audit data
# disk_full_action = HALT
# disk_error_action = SYSLOG

# Forward audit logs to remote SIEM using audisp-remote
# apt-get install audispd-plugins
# Configure /etc/audisp/plugins.d/au-remote.conf
```

### 🌍 Real-World Relevance

The Payment Card Industry Data Security Standard (PCI DSS) Requirement 10 mandates that all access to cardholder data, system components, and administrative actions must be logged and monitored. `auditd` is the primary mechanism used to satisfy this requirement on Linux. The HIPAA Security Rule similarly requires audit controls for healthcare data. In forensic investigations, auditd logs have been used to reconstruct attacker timelines and attribute actions to specific accounts with second-level precision.

### 🛡️ Defensive Measures

- Immutably lock audit rules in production (`-e 2`) after validation
- Forward audit logs to a remote, append-only log server
- Alert on modifications to `/etc/audit/` and `auditd` service stops
- Review `aureport --failed` daily for access denials indicating reconnaissance
- Retain audit logs for at least 90 days (12 months for compliance environments)

---

## 6. Firewall with iptables and ufw

### 🟢 Beginner Explanation

A host-based firewall controls which network connections are allowed to and from a Linux machine. Even if your network has a perimeter firewall, host-based firewall rules provide critical defense-in-depth — especially against lateral movement within the network. `iptables` is the traditional Linux firewall (a user-space interface to the kernel's netfilter framework). `ufw` (Uncomplicated Firewall) is a simplified front-end for iptables used primarily on Ubuntu/Debian systems.

### 🔬 Technical Deep Dive

#### ufw — Simple and Production-Ready (Debian/Ubuntu)

```bash
# Install ufw if not present
sudo apt-get install ufw -y

# Check current status
sudo ufw status verbose

# Set default policies — deny all incoming, allow all outgoing
# ⚠️ Lab Environment Only — run these only on systems where you have console access
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow specific services by name
sudo ufw allow ssh
sudo ufw allow http
sudo ufw allow https

# Allow specific ports
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Allow from specific IP (management access only)
sudo ufw allow from 192.168.1.10 to any port 22

# Deny specific port
sudo ufw deny 23/tcp     # Block Telnet

# Allow specific subnet
sudo ufw allow from 10.0.1.0/24 to any port 3306 proto tcp  # MySQL from app network only

# Delete a rule
sudo ufw delete allow http

# Enable the firewall
sudo ufw enable

# View rules with rule numbers
sudo ufw status numbered

# Reload after changes
sudo ufw reload
```

#### iptables — Direct Kernel Firewall Control

```bash
# View current rules
sudo iptables -L -v -n --line-numbers
sudo iptables -L INPUT -v -n --line-numbers

# ⚠️ Lab Environment Only — these rules are not persistent without saving them
# A misconfigured iptables rule can lock you out of a remote system

# Flush all existing rules and reset policies
sudo iptables -F       # Flush all chains
sudo iptables -X       # Delete user-defined chains
sudo iptables -Z       # Zero all counters

# Set default DROP policy (must add explicit ACCEPT rules before applying)
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT ACCEPT

# Allow established and related connections (stateful tracking)
sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow loopback interface
sudo iptables -A INPUT -i lo -j ACCEPT

# Allow SSH from management network only
sudo iptables -A INPUT -p tcp --dport 22 -s 192.168.1.0/24 -m conntrack --ctstate NEW -j ACCEPT

# Allow HTTP/HTTPS
sudo iptables -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT

# Allow ICMP (ping) — optional, but useful for diagnostics
sudo iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT

# Log dropped packets before dropping them (for debugging)
sudo iptables -A INPUT -j LOG --log-prefix "IPTABLES-DROP: " --log-level 7

# Drop everything else (already set by default policy, but explicit is clearer)
sudo iptables -A INPUT -j DROP

# Save rules to persist across reboots
sudo apt-get install iptables-persistent -y
sudo netfilter-persistent save
```

#### Making iptables Rules Persistent

```bash
# On Debian/Ubuntu
sudo netfilter-persistent save
# Rules saved to: /etc/iptables/rules.v4 and /etc/iptables/rules.v6

# On RHEL/CentOS
sudo service iptables save
# Rules saved to: /etc/sysconfig/iptables

# Verify the saved rules
cat /etc/iptables/rules.v4
```

#### nftables (Modern Replacement for iptables)

```bash
# List current nftables ruleset
sudo nft list ruleset

# Basic nftables configuration example
sudo nft add table inet filter
sudo nft add chain inet filter input { type filter hook input priority 0\; policy drop\; }
sudo nft add rule inet filter input ct state established,related accept
sudo nft add rule inet filter input iif lo accept
sudo nft add rule inet filter input tcp dport 22 accept
sudo nft add rule inet filter input tcp dport { 80, 443 } accept
```

#### Network Hardening via sysctl

```bash
# /etc/sysctl.d/99-hardening.conf — kernel network security parameters

# Prevent IP spoofing
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Disable IP source routing (used in certain attacks)
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Disable ICMP redirect acceptance (man-in-the-middle prevention)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

# Disable sending ICMP redirects (not a router)
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Enable SYN flood protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# Ignore broadcast ICMP (Smurf attack prevention)
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Disable IP forwarding (not a router)
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Log Martian packets (packets with impossible source addresses)
net.ipv4.conf.all.log_martians = 1

# Apply settings immediately
sudo sysctl --system
```

### 🌍 Real-World Relevance

The Mirai botnet and its successors spread by scanning the internet for devices with specific ports open (Telnet port 23, SSH port 22, HTTP port 80) and exploiting default credentials. A host-based firewall rule that restricts inbound connections to only necessary ports from authorised source networks would have eliminated the attack surface for millions of IoT devices. In enterprise environments, host-based firewalls are critical for containing lateral movement even after a perimeter breach.

### 🛡️ Defensive Measures

- Default-deny inbound; default-allow outbound
- Restrict SSH to management VLAN/subnet only
- Block all ports not explicitly required by the server's function
- Regularly audit firewall rules (`ufw status verbose` or `iptables -L -v -n`)
- Combine with network-level firewall (defence in depth — never rely on host firewall alone)

---

## 7. Disabling Unnecessary Services

### 🟢 Beginner Explanation

Every service running on a Linux system is an open door. A web server that is also running an FTP server, a mail server, and a Samba share has four times the attack surface of one that only runs the web server. Disabling services that are not needed reduces this attack surface and makes the system easier to monitor and maintain.

### 🔬 Technical Deep Dive

#### Auditing Running Services with systemctl

```bash
# List all active (running) units
sudo systemctl list-units --type=service --state=active

# List all enabled services (will start at boot)
sudo systemctl list-unit-files --type=service --state=enabled

# List all failed services
sudo systemctl list-units --type=service --state=failed

# Get detailed information about a service
sudo systemctl status sshd
sudo systemctl status apache2

# Check what a service does and its configuration
sudo systemctl cat nginx
sudo systemctl show nginx --property=ExecStart,User,Group
```

#### Identifying Services Listening on Network Ports

```bash
# List all network listening ports and their associated processes
sudo ss -tlnp        # TCP listening ports
sudo ss -ulnp        # UDP listening ports
sudo ss -tlnup       # Both TCP and UDP

# Alternative: netstat (may need net-tools package)
sudo netstat -tlnp

# Find the process using a specific port
sudo ss -tlnp | grep ':80 '
sudo fuser 80/tcp

# Cross-reference with running services
sudo lsof -i -P -n | grep LISTEN
```

#### Disabling Unnecessary Services

```bash
# ⚠️ Lab Environment Only — verify service purpose before disabling in production

# Stop a running service immediately
sudo systemctl stop avahi-daemon    # mDNS/DNS-SD — usually unnecessary on servers

# Disable a service so it does not start at boot
sudo systemctl disable avahi-daemon

# Stop and disable in one command
sudo systemctl disable --now avahi-daemon

# Mask a service to prevent it from being started manually or by other services
sudo systemctl mask bluetooth
sudo systemctl mask cups          # Print system — disable on servers

# Common services to evaluate for disabling on hardened servers:
services_to_review=(
    "avahi-daemon"      # mDNS — enables zero-config networking, not needed on servers
    "bluetooth"         # Bluetooth — servers don't need Bluetooth
    "cups"              # Printing — servers rarely print
    "rpcbind"           # RPC portmapper — needed only for NFS
    "nfs-server"        # NFS — disable if not sharing filesystems
    "vsftpd"            # FTP — use SFTP instead
    "telnet"            # Telnet — plaintext, never acceptable
    "rsh-server"        # Remote shell — obsolete and insecure
    "rlogin"            # Remote login — obsolete and insecure
    "nis"               # Network Information Service — legacy, insecure
    "snmpd"             # SNMP — disable if not monitoring
    "postfix"           # Mail transfer agent — disable if no local mail needed
    "sendmail"          # Alternative MTA — disable if not needed
    "xinetd"            # Inetd superserver — obsolete
    "tftp"              # Trivial FTP — insecure, no auth
    "rsync"             # Remote sync daemon — use SSH-based rsync instead
)

for svc in "${services_to_review[@]}"; do
    if systemctl is-enabled "$svc" 2>/dev/null | grep -q enabled; then
        echo "ENABLED (review): $svc"
    elif systemctl is-active "$svc" 2>/dev/null | grep -q active; then
        echo "ACTIVE (review): $svc"
    fi
done
```

#### Removing Unnecessary Packages

The safest way to disable a service is to remove the package entirely:

```bash
# Remove a package and its configuration files
sudo apt-get purge telnet rsh-client rsh-redone-client talk ntalk -y

# Remove orphaned dependencies
sudo apt-get autoremove -y

# List installed packages and check for security-relevant ones
dpkg -l | grep -E 'telnet|ftp|rsh|talk|finger|rlogind'

# Check for packages that are not from the official repository
apt-cache policy <package_name>
```

#### Securing inetd / xinetd

If xinetd is running, audit its configuration:

```bash
# Check if xinetd is running
sudo systemctl status xinetd

# List all services managed by xinetd
ls /etc/xinetd.d/
cat /etc/xinetd.d/*

# Disable specific services in xinetd by setting disable = yes
sudo nano /etc/xinetd.d/telnet
# Add: disable = yes
```

### 🌍 Real-World Relevance

The 2017 Equifax breach, which exposed data on 147 million people, was in part facilitated by an Apache Struts web application vulnerability — but post-breach analysis revealed that internal network segmentation was poor and services were running on systems where they were not needed. An attacker who compromises one service should find a minimal environment, not a treasure trove of adjacent attack surfaces.

### 🛡️ Defensive Measures

- Review running services after every major system change
- Use `nmap -sV localhost` (from localhost) to validate what is externally visible
- Document the authorised services for each server type; alert on deviations
- Combine service restriction with firewall rules for defence in depth

---

## 8. CIS Benchmark Alignment

### 🟢 Beginner Explanation

The Center for Internet Security (CIS) publishes detailed hardening benchmarks for virtually every major operating system and application. These benchmarks represent consensus-based best practices from security professionals worldwide. Aligning your Linux configuration with the CIS Benchmark provides a documented, auditable, and internationally recognised security baseline.

### 🔬 Technical Deep Dive

#### CIS Benchmark Levels

| Level | Description |
|-------|-------------|
| **Level 1** | Essential security controls that should be applied to all systems. Minimal performance impact, suitable for all environments |
| **Level 2** | Deeper hardening for higher-security environments. May impact functionality or require additional configuration effort |

#### Key CIS Ubuntu Linux Benchmark Controls (Selected)

```bash
# CIS 1.1.1 — Disable unused filesystems
# Add to /etc/modprobe.d/blacklist.conf:
# install cramfs /bin/true
# install freevxfs /bin/true
# install jffs2 /bin/true
# install hfs /bin/true
# install hfsplus /bin/true
# install squashfs /bin/true
# install udf /bin/true

# CIS 1.1.3-1.1.5 — /tmp partition hardening
# /etc/fstab entry:
# tmpfs  /tmp  tmpfs  defaults,rw,nosuid,nodev,noexec,relatime  0 0
sudo mount -o remount,nosuid,nodev,noexec /tmp

# CIS 3.1.1 — Disable IPv6 if not required
# /etc/sysctl.d/60-disable-ipv6.conf:
# net.ipv6.conf.all.disable_ipv6 = 1
# net.ipv6.conf.default.disable_ipv6 = 1

# CIS 4.1 — Configure auditd (see Section 5)
sudo systemctl is-enabled auditd

# CIS 5.2.x — SSH server configuration (see Section 3)
sudo sshd -T | grep -E 'permitrootlogin|passwordauthentication|maxauthtries|protocol'

# CIS 5.3.x — Configure PAM (password quality)
grep pam_pwquality /etc/pam.d/common-password

# CIS 5.4.1 — Password hashing algorithm
grep '^ENCRYPT_METHOD' /etc/login.defs

# CIS 5.4.2 — Minimum days between password changes
grep '^PASS_MIN_DAYS' /etc/login.defs

# CIS 6.1.x — System file permissions audit
stat /etc/passwd /etc/shadow /etc/group /etc/gshadow

# CIS 6.2.x — User and group auditing
awk -F: '($3 == 0)' /etc/passwd           # CIS 6.2.1 — Only root with UID 0
awk -F: '($2 == "")' /etc/shadow           # CIS 6.2.2 — No empty passwords
```

#### Automated CIS Assessment with Lynis

Lynis is an open-source security auditing tool that checks system configuration against security best practices and provides a hardening index:

```bash
# Install Lynis
sudo apt-get install lynis -y

# Run a full system audit
sudo lynis audit system

# Run without interaction
sudo lynis audit system --quiet

# Generate a report
sudo lynis audit system --report-file /var/log/lynis-report.dat

# Check specific section
sudo lynis audit system --tests-from-group authentication

# Key output sections to review:
# - Hardening index score (target: 80+)
# - Warnings (items requiring immediate attention)
# - Suggestions (items to improve)
# - Enabled/disabled status of key controls

# Review Lynis findings
sudo cat /var/log/lynis.log | grep Warning
sudo cat /var/log/lynis.log | grep Suggestion
```

#### OpenSCAP for Automated Compliance Scanning

```bash
# Install OpenSCAP (RHEL/CentOS)
sudo yum install openscap-scanner scap-security-guide -y

# Install on Debian/Ubuntu
sudo apt-get install openscap-scanner libopenscap8 -y

# Scan against CIS benchmark (example for RHEL)
sudo oscap xccdf eval \
    --profile xccdf_org.ssgproject.content_profile_cis \
    --report /var/log/scap-report.html \
    /usr/share/xml/scap/ssg/content/ssg-rhel8-ds.xml

# The generated HTML report shows pass/fail for each CIS control
```

### 🌍 Real-World Relevance

Many regulatory frameworks (PCI DSS, HIPAA, FedRAMP, SOC 2) reference CIS Benchmarks as an acceptable hardening standard. Organisations that can demonstrate CIS Benchmark compliance on their Linux systems significantly reduce their audit burden and demonstrate due care — which is relevant not only for compliance but also in legal proceedings following a breach.

### 🛡️ Defensive Measures

- Run Lynis audits monthly and track the hardening index over time
- Integrate OpenSCAP into your CI/CD pipeline for infrastructure-as-code validation
- Use CIS Benchmark Level 1 as your baseline for all servers
- Apply Level 2 controls for systems handling sensitive data or with internet exposure
- Document deviations from the benchmark and obtain explicit approval for each

---

## 9. Module Practice Challenge

> **Scenario:** You have been given access to a freshly provisioned Ubuntu 22.04 LTS server. It has been deployed with default settings by a developer who prioritised getting the service running quickly over security. Your task is to harden it to a production-ready standard.

### 🏁 Challenge Tasks

**Tier 1 — Foundation**
1. Review `/etc/passwd` and `/etc/shadow`: List all accounts with interactive shells. Are there any accounts that should not have them? Fix any issues you find.
2. Run `find / -perm -4000 2>/dev/null` and document all SUID binaries. Identify any that are not in the expected set.
3. Check `/etc/ssh/sshd_config` against the hardened configuration in Section 3. Apply at least 8 hardening settings, test with `sshd -t`, then reload SSH.
4. Run `sudo systemctl list-unit-files --state=enabled` and identify 3 or more services that should be disabled on a minimal server.
5. Generate an SSH Ed25519 key pair and verify that you can authenticate using key-based auth before disabling password authentication.

**Tier 2 — Intermediate**
6. Install and configure `auditd`. Apply the ruleset from Section 5, then use `ausearch -k identity` after modifying `/etc/passwd` to verify events are being captured.
7. Install and configure `ufw`: default deny inbound, allow SSH from a specific subnet only, allow HTTPS, and reload. Verify with `ufw status verbose`.
8. Configure `fail2ban` for SSH with a max of 3 retry attempts and a 1-hour ban. Test by generating 3 failed SSH logins from a test host and verify the ban.
9. Install `libpam-pwquality` and configure minimum 14-character passwords with complexity requirements.
10. Review and correct permissions on `/etc/shadow`, `/etc/sudoers`, and `~/.ssh/authorized_keys`.

**Tier 3 — Advanced**
11. Install Lynis and run a full system audit. Record the initial hardening index. Apply the top 5 suggestions and re-run — what is your new score?
12. Write a Bash script that checks for: (a) accounts with UID 0 other than root, (b) world-writable files in `/etc`, (c) SUID binaries not in an approved list, and (d) any active listening service not in an approved list. Output a formatted report.
13. Configure `/etc/sysctl.d/99-hardening.conf` with the network hardening settings from Section 6 and apply them. Verify with `sysctl -a | grep ip_forward`.
14. Produce a one-page hardening checklist documenting: every change made, the CIS Benchmark control it addresses, and the risk it mitigates.

### ✅ Success Criteria

- `sudo lynis audit system` hardening index ≥ 70 (starting from a default Ubuntu install)
- `sudo auditctl -l` shows at least 10 active audit rules
- `sudo ufw status verbose` shows default deny with only authorised ports open
- `sudo sshd -T | grep passwordauthentication` returns `no`
- No accounts in `/etc/passwd` with UID 0 other than root
- `sudo ss -tlnp` shows no unexpected listening services

---

← [Back to System Security Overview](./README.md) | [Next: Service Auditing →](./Service_Auditing.md)
