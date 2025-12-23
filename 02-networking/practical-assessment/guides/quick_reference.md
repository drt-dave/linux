# Quick Reference Guide
## Nmap Commands and Security Concepts

This is a condensed reference for quick lookups during security assessments.

---

## Essential Nmap Commands

### Host Discovery
```bash
# Ping sweep (find active hosts)
nmap -sn 192.168.1.0/24

# ARP scan (local network only)
sudo nmap -PR 192.168.1.0/24

# Skip host discovery (assume all hosts up)
nmap -Pn 192.168.1.0/24
```

### Port Scanning
```bash
# Quick scan (top 1000 ports)
nmap 192.168.1.1

# Scan specific ports
nmap -p 22,80,443 192.168.1.1

# Scan all ports
nmap -p- 192.168.1.1

# Scan port range
nmap -p 1-1000 192.168.1.1

# Fast scan (top 100 ports)
nmap -F 192.168.1.1
```

### Service Detection
```bash
# Version detection
nmap -sV 192.168.1.1

# Aggressive scan (OS, version, scripts, traceroute)
nmap -A 192.168.1.1

# OS detection
nmap -O 192.168.1.1
```

### Scan Types
```bash
# TCP SYN scan (stealth, requires root)
sudo nmap -sS 192.168.1.1

# TCP Connect scan (no root needed)
nmap -sT 192.168.1.1

# UDP scan
sudo nmap -sU 192.168.1.1

# Combined TCP + UDP
sudo nmap -sS -sU 192.168.1.1
```

### NSE Scripts
```bash
# Default scripts
nmap -sC 192.168.1.1

# Specific script
nmap --script http-title 192.168.1.1

# Script category
nmap --script vuln 192.168.1.1

# Multiple scripts
nmap --script ssh-auth-methods,ssh-hostkey 192.168.1.1

# All SMB scripts
nmap --script smb* 192.168.1.1
```

### Output Options
```bash
# Normal output
nmap -oN scan.txt 192.168.1.1

# XML output
nmap -oX scan.xml 192.168.1.1

# Grepable output
nmap -oG scan.gnmap 192.168.1.1

# All formats
nmap -oA scan 192.168.1.1
```

### Timing and Performance
```bash
# Timing templates (0=slow, 5=fast)
nmap -T4 192.168.1.1

# Adjust parallelism
nmap --min-parallelism 100 192.168.1.1

# Adjust timeout
nmap --host-timeout 30m 192.168.1.1
```

### Useful Combinations
```bash
# Common vulnerability scan
nmap -sV -sC --script vuln 192.168.1.1

# Full TCP scan with version detection
nmap -p- -sV -sC -T4 192.168.1.1

# Quick network sweep with service detection
nmap -sV -T4 -F 192.168.1.0/24

# Comprehensive scan (save all output)
nmap -sS -sV -sC -A -p- -T4 -oA full_scan 192.168.1.1
```

---

## Common Ports Quick Reference

| Port | Service | Security Notes |
|------|---------|----------------|
| 21 | FTP | Often unencrypted, anonymous access? |
| 22 | SSH | Check auth methods, version |
| 23 | Telnet | Unencrypted, avoid if possible |
| 25 | SMTP | Email server, relay configuration? |
| 53 | DNS | Zone transfer vulnerability? |
| 80 | HTTP | Web vulnerabilities, directory traversal |
| 110 | POP3 | Email retrieval, credentials in clear? |
| 135 | MSRPC | Windows RPC, enumeration possible |
| 139 | NetBIOS | Windows file sharing, null sessions? |
| 143 | IMAP | Email access, encryption? |
| 443 | HTTPS | SSL/TLS version, certificate validity |
| 445 | SMB | File sharing, EternalBlue, relay attacks |
| 1433 | MSSQL | Database, default credentials? |
| 3306 | MySQL | Database, remote access allowed? |
| 3389 | RDP | Remote desktop, brute force target |
| 5432 | PostgreSQL | Database, authentication |
| 5900 | VNC | Remote desktop, weak auth common |
| 8080 | HTTP-Alt | Alternative web server |
| 8443 | HTTPS-Alt | Alternative secure web |

---

## SMB Enumeration Commands

### Nmap SMB Scripts
```bash
# SMB version detection
nmap -p 445 --script smb-protocols 192.168.1.2

# SMB security configuration
nmap -p 445 --script smb-security-mode 192.168.1.2

# SMB OS discovery
nmap -p 445 --script smb-os-discovery 192.168.1.2

# List shares
nmap -p 445 --script smb-enum-shares 192.168.1.2

# List users
nmap -p 445 --script smb-enum-users 192.168.1.2

# All SMB vulnerabilities
nmap -p 445 --script smb-vuln* 192.168.1.2
```

### smbclient Commands
```bash
# List shares (no auth)
smbclient -L //192.168.1.2 -N

# List shares (with credentials)
smbclient -L //192.168.1.2 -U username

# Connect to share
smbclient //192.168.1.2/sharename -U username
```

### enum4linux
```bash
# Full enumeration
enum4linux -a 192.168.1.2

# User enumeration
enum4linux -U 192.168.1.2

# Share enumeration
enum4linux -S 192.168.1.2
```

---

## SSH Enumeration Commands

### Check Authentication Methods
```bash
nmap -p 22 --script ssh-auth-methods 192.168.1.1
```

### Check Supported Algorithms
```bash
nmap -p 22 --script ssh2-enum-algos 192.168.1.1
```

### Check Host Key
```bash
nmap -p 22 --script ssh-hostkey 192.168.1.1
```

### Manual Connection Test
```bash
# Test connection
ssh user@192.168.1.1

# Specify key
ssh -i keyfile user@192.168.1.1

# Verbose (see auth methods)
ssh -v user@192.168.1.1
```

---

## Vulnerability Research

### searchsploit (Local Exploit-DB)
```bash
# Search for exploits
searchsploit dropbear

# Search specific version
searchsploit "dropbear 2019"

# Case-insensitive
searchsploit -i dropbear

# Search in title only
searchsploit -t ssh

# Copy exploit to current directory
searchsploit -m exploits/linux/remote/12345.py
```

### Online Resources
```bash
# CVE Database
https://cve.mitre.org
https://nvd.nist.gov

# Exploit Database
https://exploit-db.com

# Packet Storm
https://packetstormsecurity.com

# Security Focus
https://www.securityfocus.com
```

---

## Risk Rating Guide

### CVSS Severity Ratings
- **Critical (9.0-10.0):** Immediate action required
- **High (7.0-8.9):** Important to fix quickly
- **Medium (4.0-6.9):** Should be fixed
- **Low (0.1-3.9):** Fix when convenient
- **None (0.0):** Informational

### CVSS Metrics
**Base Score Calculation:**
- Attack Vector (Network/Adjacent/Local/Physical)
- Attack Complexity (Low/High)
- Privileges Required (None/Low/High)
- User Interaction (None/Required)
- Scope (Unchanged/Changed)
- Confidentiality Impact (None/Low/High)
- Integrity Impact (None/Low/High)
- Availability Impact (None/Low/High)

---

## Common Vulnerabilities Quick Lookup

### SSH Vulnerabilities
- **Password-only auth:** Brute force attacks
- **Weak ciphers:** CBC mode vulnerabilities
- **Old versions:** Known CVEs (check version)
- **Default port 22:** Easy to find

### SMB Vulnerabilities
- **SMBv1 enabled:** EternalBlue (MS17-010)
- **Signing not required:** Relay attacks
- **Null sessions:** Information disclosure
- **Weak passwords:** Brute force

### Web Server Vulnerabilities
- **Directory listing:** Information disclosure
- **Default pages:** Version disclosure
- **Unpatched software:** Known CVEs
- **SSL/TLS issues:** Weak ciphers, old protocols

### Database Vulnerabilities
- **Remote access:** Should be restricted
- **Default credentials:** Common attack
- **No encryption:** Data in transit exposed
- **SQL injection:** Application vulnerability

---

## Network Subnetting Quick Reference

### CIDR Notation
| CIDR | Subnet Mask | Usable IPs | Total IPs |
|------|-------------|------------|-----------|
| /24 | 255.255.255.0 | 254 | 256 |
| /25 | 255.255.255.128 | 126 | 128 |
| /26 | 255.255.255.192 | 62 | 64 |
| /27 | 255.255.255.224 | 30 | 32 |
| /28 | 255.255.255.240 | 14 | 16 |
| /29 | 255.255.255.248 | 6 | 8 |
| /30 | 255.255.255.252 | 2 | 4 |
| /32 | 255.255.255.255 | 1 | 1 |

### Private IP Ranges
- **Class A:** 10.0.0.0 - 10.255.255.255 (10.0.0.0/8)
- **Class B:** 172.16.0.0 - 172.31.255.255 (172.16.0.0/12)
- **Class C:** 192.168.0.0 - 192.168.255.255 (192.168.0.0/16)

---

## Essential Linux Commands for Pentesters

### Network Information
```bash
# Show IP addresses
ip addr show

# Show routing table
ip route show

# Show ARP cache
ip neighbor show

# Show listening ports
ss -tuln
netstat -tuln

# Show network connections
ss -tunap
netstat -tunap
```

### Process and Service Management
```bash
# List processes
ps aux

# Find process by name
ps aux | grep ssh

# Kill process
kill -9 [PID]

# Check service status
systemctl status ssh
```

### File Operations
```bash
# Find files
find / -name "*.conf" 2>/dev/null

# Search in files
grep -r "password" /etc/

# Check file permissions
ls -la /etc/shadow
```

---

## Report Writing Checklist

### Executive Summary
- [ ] High-level overview
- [ ] Key findings (3-5 bullet points)
- [ ] Overall risk rating
- [ ] Primary recommendations
- [ ] Business impact statement

### Methodology
- [ ] Scope definition
- [ ] Tools used
- [ ] Testing approach
- [ ] Standards followed
- [ ] Timeline

### Detailed Findings
For each finding:
- [ ] Title (clear and concise)
- [ ] Severity rating (Critical/High/Medium/Low)
- [ ] CVSS score
- [ ] Affected systems/IPs
- [ ] Technical description
- [ ] Exploitation scenario
- [ ] Business impact
- [ ] Evidence (screenshots, command output)
- [ ] Remediation steps (specific and actionable)
- [ ] References (CVEs, articles)

### Remediation Roadmap
- [ ] Immediate actions (24-48 hours)
- [ ] Short-term (1-2 weeks)
- [ ] Medium-term (1-3 months)
- [ ] Long-term (ongoing)
- [ ] Prioritized by risk

### Appendices
- [ ] Raw scan data
- [ ] Tool outputs
- [ ] Network diagrams
- [ ] References
- [ ] Glossary of terms

---

## Remediation Quick Reference

### SSH Hardening
```bash
# Generate SSH key pair
ssh-keygen -t ed25519 -C "admin@server"

# Copy key to server
ssh-copy-id user@server

# Edit SSH config (/etc/ssh/sshd_config)
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
Port 2222  # Change default port

# Restart SSH
systemctl restart sshd
```

### Windows SMB Hardening
```powershell
# Require SMB signing (PowerShell)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "RequireSecuritySignature" -Value 1

# Disable SMBv1
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol

# Enable SMB encryption
Set-SmbServerConfiguration -EncryptData $true

# Restart SMB service
Restart-Service LanmanServer
```

### Firewall Rules
```bash
# Linux (iptables)
iptables -A INPUT -p tcp --dport 22 -s 192.168.1.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j DROP

# Linux (ufw)
ufw allow from 192.168.1.0/24 to any port 22
ufw enable
```

```powershell
# Windows (PowerShell)
New-NetFirewallRule -DisplayName "Allow SSH from LAN" -Direction Inbound -Protocol TCP -LocalPort 22 -RemoteAddress 192.168.1.0/24 -Action Allow
```

---

## Common NSE Scripts Reference

### Discovery
- `banner` - Grab service banners
- `dns-brute` - DNS subdomain brute force
- `smb-os-discovery` - SMB OS information
- `ssh-hostkey` - SSH host key information

### Vulnerability Detection
- `vuln` - All vulnerability scripts
- `smb-vuln*` - All SMB vulnerability scripts
- `http-vuln*` - All HTTP vulnerability scripts
- `ssl-heartbleed` - Heartbleed detection

### Enumeration
- `smb-enum-shares` - List SMB shares
- `smb-enum-users` - List SMB users
- `http-enum` - HTTP directory enumeration
- `ftp-anon` - Test for anonymous FTP

### Authentication
- `ssh-auth-methods` - SSH authentication methods
- `http-auth` - HTTP authentication testing
- `smb-security-mode` - SMB security configuration

---

## Keyboard Shortcuts (Terminal)

### Essential Shortcuts
- `Ctrl+C` - Interrupt current command
- `Ctrl+Z` - Suspend current command
- `Ctrl+D` - Exit/logout
- `Ctrl+L` - Clear screen (same as `clear`)
- `Ctrl+A` - Move to beginning of line
- `Ctrl+E` - Move to end of line
- `Ctrl+R` - Search command history
- `Ctrl+U` - Delete from cursor to beginning
- `Ctrl+K` - Delete from cursor to end
- `Tab` - Auto-complete

---

## Environment Variables

### Useful Variables
```bash
# Set working directory
export WORKDIR=/tmp/assessment

# Set target IP
export TARGET=192.168.1.1

# Set target network
export NETWORK=192.168.1.0/24

# Use in commands
nmap -sV $TARGET
nmap -sn $NETWORK
```

---

## One-Liner Cheat Sheet

### Quick Scans
```bash
# Quick vulnerability scan
nmap -sV --script vuln [target]

# Quick web server check
curl -I http://[target]

# Check if port is open
nc -zv [target] [port]

# Grab banner
nc [target] [port]
```

### Data Processing
```bash
# Extract IPs from nmap output
grep "Nmap scan report" scan.txt | awk '{print $5}'

# Extract open ports
grep "open" scan.txt | awk '{print $1}'

# Sort IPs
sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n ips.txt
```

---

## Important Reminders

### Before Every Assessment
1. ✅ Verify authorization in writing
2. ✅ Understand scope boundaries
3. ✅ Set up logging/documentation
4. ✅ Create backup of data
5. ✅ Test tools in lab first
6. ✅ Inform relevant parties
7. ✅ Have incident response contact

### During Assessment
1. 📝 Document everything
2. 📸 Screenshot evidence
3. ⏰ Note timestamps
4. 🔍 Double-check findings
5. 🛡️ Avoid breaking things
6. 🤝 Communicate progress
7. 💾 Save all outputs

### After Assessment
1. 📊 Verify all findings
2. 📝 Write detailed report
3. 🗑️ Secure delete sensitive data
4. 📢 Present findings professionally
5. 🤝 Provide remediation support
6. 📅 Schedule re-test
7. 🔒 Maintain confidentiality

---

## Emergency Contacts

### If Something Goes Wrong

1. **Stop testing immediately**
2. **Document what happened**
3. **Notify authorized contact**
4. **Preserve evidence**
5. **Follow incident response plan**

### Common Issues

**Accidentally crashed a service:**
- Stop all testing
- Contact system owner
- Document the command that caused it
- Assist with recovery if possible

**Found critical vulnerability being actively exploited:**
- Notify client immediately (out of band)
- Document evidence
- Follow responsible disclosure
- Do NOT attempt to "clean up" the intrusion

**Lost access to testing machine:**
- Use backup credentials
- Contact network administrator
- Document for report
- Resume from last known state

---

## Learning Resources Quick Links

### Practice Platforms
- **TryHackMe:** https://tryhackme.com
- **HackTheBox:** https://hackthebox.eu
- **VulnHub:** https://vulnhub.com
- **OverTheWire:** https://overthewire.org

### Reference
- **OWASP:** https://owasp.org
- **NIST:** https://nist.gov
- **CWE:** https://cwe.mitre.org
- **CVE:** https://cve.mitre.org

### Documentation
- **Nmap:** https://nmap.org/book/
- **Metasploit:** https://metasploit.help
- **PTES:** http://pentest-standard.org

---

**This quick reference should be printed or kept easily accessible during assessments!**
