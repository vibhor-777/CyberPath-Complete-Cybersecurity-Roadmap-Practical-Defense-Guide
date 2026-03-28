# H — Hardening

## Beginner Explanation
Hardening is the process of reducing a system's attack surface by removing unnecessary features, closing unused ports, applying patches, and configuring security settings. A freshly installed OS is like a new house with every window and door unlocked — hardening means locking everything that doesn't need to be open.

## Technical Deep Dive
### CIS Benchmarks
The Center for Internet Security (CIS) publishes free hardening benchmarks for every major OS. Each control is rated Level 1 (essential, minimal impact) or Level 2 (defense-in-depth, higher impact).

### Windows Hardening Essentials
```powershell
# Disable SMBv1 (EternalBlue target)
Set-SmbServerConfiguration -EnableSMB1Protocol $false

# Enable Windows Defender Credential Guard
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 1 /f

# Disable unnecessary services
Stop-Service -Name "Telnet" -ErrorAction SilentlyContinue
Set-Service  -Name "Telnet" -StartupType Disabled -ErrorAction SilentlyContinue

# Enable audit policies
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable
```

### Linux Hardening Essentials
```bash
# Disable root SSH login
sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
systemctl restart sshd

# Enable automatic security updates (Debian/Ubuntu)
apt-get install -y unattended-upgrades
dpkg-reconfigure --priority=low unattended-upgrades

# Kernel hardening via sysctl
cat >> /etc/sysctl.conf << 'SYSCTL'
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
kernel.randomize_va_space = 2
kernel.dmesg_restrict = 1
SYSCTL
sysctl -p
```

## Real-World Relevance
The **2017 Equifax breach** exploited an unpatched Apache Struts vulnerability (CVE-2017-5638) that had a patch available for two months. A hardening process including timely patching would have prevented the exposure of 147 million records.

## Defensive Measures
1. Run CIS-CAT Pro or Lynis to score your current hardening level
2. Apply CIS Level 1 benchmarks to all new systems before deployment
3. Integrate hardening into your image/AMI build process
4. Audit hardening posture quarterly

## Practice Challenge
Download and run Lynis on a lab Linux VM: `sudo lynis audit system`. Review the hardening index score and implement the top 5 recommendations. Re-run and document improvement.
