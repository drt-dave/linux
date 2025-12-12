# Lesson 2.2: Network Scanning & Enumeration

## Objective
Master network scanning techniques using Nmap and other tools to discover hosts, open ports, services, and potential vulnerabilities.

---

## Port Scanning Fundamentals

### What is Port Scanning?

Port scanning is the process of probing a target to identify:
- Open ports (services accepting connections)
- Closed ports (no service listening)
- Filtered ports (firewall blocking)

### Port States

```
OPEN     - Service accepting connections
CLOSED   - No service on port, but host is up
FILTERED - Firewall/filter blocking probe
UNFILTERED - Accessible but state unclear
OPEN|FILTERED - Nmap cannot determine
CLOSED|FILTERED - Nmap cannot determine
```

---

## Nmap - The Network Mapper

### Basic Syntax

```bash
nmap [Scan Type] [Options] <target>
```

### Target Specification

```bash
# Single host
nmap 192.168.1.100

# Multiple hosts
nmap 192.168.1.100 192.168.1.101

# IP range
nmap 192.168.1.1-254
nmap 192.168.1.0/24

# Subnet
nmap 10.0.0.0/8

# Multiple subnets
nmap 192.168.1.0/24 10.0.0.0/24

# From file
nmap -iL targets.txt

# Exclude hosts
nmap 192.168.1.0/24 --exclude 192.168.1.1
```

---

## Scan Types

### 1. TCP Connect Scan (-sT)

**Full three-way handshake**

```bash
nmap -sT 192.168.1.100
```

**How it works:**
```
Scanner          Target
  │                │
  ├─── SYN ───────> │  If OPEN:
  │ <─ SYN-ACK ────┤
  ├─── ACK ───────> │  Connection established
  ├─── RST ───────> │  Immediate disconnect

  ├─── SYN ───────> │  If CLOSED:
  │ <─── RST ──────┤  Port closed
```

**Pros:**
- Works without root privileges
- Reliable
- Completes handshake

**Cons:**
- Logged by target system
- Noisy
- Slower than SYN scan

---

### 2. SYN Scan (-sS) "Stealth Scan"

**Half-open scan - never completes handshake**

```bash
sudo nmap -sS 192.168.1.100
```

**How it works:**
```
Scanner          Target
  │                │
  ├─── SYN ───────> │  If OPEN:
  │ <─ SYN-ACK ────┤
  ├─── RST ───────> │  Never complete! (stealthier)

  ├─── SYN ───────> │  If CLOSED:
  │ <─── RST ──────┤
```

**Pros:**
- Stealthier (may not be logged)
- Faster
- Default scan with root

**Cons:**
- Requires root/admin privileges
- Can crash unstable services

---

### 3. UDP Scan (-sU)

**Scan UDP ports**

```bash
sudo nmap -sU 192.168.1.100
```

**Important UDP ports:**
```
53   - DNS
67/68 - DHCP
69   - TFTP
123  - NTP
161  - SNMP
500  - IKE (VPN)
514  - Syslog
```

**How it works:**
```
Scanner          Target
  │                │
  ├─ UDP packet ──> │  If OPEN: No response (or service response)
  │                │
  ├─ UDP packet ──> │  If CLOSED:
  │ <─ ICMP Port ──┤  ICMP port unreachable
      Unreachable
```

**Challenges:**
- Very slow (ICMP rate limiting)
- Unreliable (packet loss)
- Requires root

**Speed it up:**
```bash
sudo nmap -sU --top-ports 20 192.168.1.100
sudo nmap -sU -F 192.168.1.100  # Fast mode
```

---

### 4. NULL, FIN, Xmas Scans

**Bypass simple firewalls**

```bash
# NULL scan - no flags set
sudo nmap -sN 192.168.1.100

# FIN scan - only FIN flag
sudo nmap -sF 192.168.1.100

# Xmas scan - FIN, PSH, URG flags (lit up like Christmas tree)
sudo nmap -sX 192.168.1.100
```

**Theory:**
- If port is OPEN: No response
- If port is CLOSED: RST response

**Limitations:**
- Doesn't work on Windows
- Many firewalls detect these

---

### 5. ACK Scan (-sA)

**Firewall rule detection**

```bash
sudo nmap -sA 192.168.1.100
```

**Purpose:**
- Determine if firewall is stateful
- Map firewall rulesets
- Doesn't determine open/closed

**Result:**
- UNFILTERED - No firewall or allows ACK
- FILTERED - Firewall blocking

---

## Port Specification

```bash
# Single port
nmap -p 80 <target>

# Multiple ports
nmap -p 80,443,8080 <target>

# Port range
nmap -p 1-1000 <target>

# All ports (1-65535)
nmap -p- <target>

# Top 100 most common
nmap --top-ports 100 <target>

# Fast scan (top 100)
nmap -F <target>

# Specific protocol
nmap -p U:53,T:80 <target>  # UDP 53, TCP 80
```

---

## Host Discovery

### Ping Scan (-sn)

**Discover live hosts without port scanning**

```bash
nmap -sn 192.168.1.0/24
```

**Sends:**
- ICMP echo request
- TCP SYN to port 443
- TCP ACK to port 80
- ICMP timestamp request

**Skip ping (assume host is up):**
```bash
nmap -Pn <target>
```
Use when ICMP is blocked.

### ARP Scan (Local Network)

```bash
sudo nmap -PR 192.168.1.0/24
```

**Best for local network discovery** - very fast and reliable.

---

## Service and Version Detection

### Version Detection (-sV)

```bash
nmap -sV <target>
```

**Intensity levels:**
```bash
nmap -sV --version-intensity 0 <target>  # Light (fast)
nmap -sV --version-intensity 9 <target>  # Aggressive (slow)
```

**Example output:**
```
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.3
80/tcp  open  http     Apache httpd 2.4.41
```

**Why important:**
- Identify vulnerable versions
- Determine attack vectors
- Find default credentials

---

## OS Detection

### OS Fingerprinting (-O)

```bash
sudo nmap -O <target>
```

**How it works:**
- TCP/IP stack fingerprinting
- Analyzes responses to crafted packets
- Compares to database of OS signatures

**Aggressive detection:**
```bash
sudo nmap -O --osscan-guess <target>
```

**Example output:**
```
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.6
```

---

## NSE (Nmap Scripting Engine)

### Default Scripts

```bash
nmap -sC <target>
```

Runs safe, useful scripts for enumeration.

### Specific Scripts

```bash
# List all scripts
ls /usr/share/nmap/scripts/

# Search for scripts
nmap --script-help "*smb*"

# Run specific script
nmap --script=http-title <target>
nmap --script=smb-os-discovery <target>
```

### Script Categories

```bash
# Vulnerability detection
nmap --script vuln <target>

# All authentication scripts
nmap --script auth <target>

# Brute force scripts
nmap --script brute <target>

# Discovery scripts
nmap --script discovery <target>

# Exploit scripts (dangerous!)
nmap --script exploit <target>
```

### Useful Scripts

```bash
# HTTP enumeration
nmap --script http-enum <target>

# SMB enumeration
nmap --script smb-enum-shares,smb-enum-users <target>

# SSL/TLS information
nmap --script ssl-cert,ssl-enum-ciphers -p 443 <target>

# DNS enumeration
nmap --script dns-brute <domain>

# Check for vulnerabilities
nmap --script vuln <target>
```

---

## Timing and Performance

### Timing Templates (-T)

```bash
-T0  Paranoid   - Very slow, IDS evasion
-T1  Sneaky     - Slow, IDS evasion
-T2  Polite     - Slow, less bandwidth
-T3  Normal     - Default
-T4  Aggressive - Fast, assumes fast network
-T5  Insane     - Very fast, may miss ports
```

**Recommended:**
```bash
nmap -T4 <target>  # Most common in pentesting
```

### Custom Timing

```bash
# Minimum packets per second
nmap --min-rate 1000 <target>

# Maximum packets per second
nmap --max-rate 100 <target>

# Delay between probes
nmap --scan-delay 1s <target>
```

---

## Output Formats

### Save Results

```bash
# Normal output
nmap -oN scan.txt <target>

# XML output (for tools)
nmap -oX scan.xml <target>

# Grepable output
nmap -oG scan.gnmap <target>

# All formats
nmap -oA scan <target>  # Creates scan.nmap, scan.xml, scan.gnmap
```

### Real-time Output

```bash
# Verbose
nmap -v <target>

# Very verbose
nmap -vv <target>

# Debug (very detailed)
nmap -d <target>
```

---

## Practical Scanning Strategies

### Quick Network Survey

```bash
# Find live hosts
sudo nmap -sn 192.168.1.0/24

# Quick port scan on live hosts
sudo nmap -T4 -F 192.168.1.0/24

# Save results
sudo nmap -T4 -F 192.168.1.0/24 -oA quick_scan
```

### Comprehensive Single Host Scan

```bash
# Full comprehensive scan
sudo nmap -sS -sV -O -A -p- -T4 <target> -oA full_scan

# Breakdown:
# -sS: SYN scan
# -sV: Version detection
# -O:  OS detection
# -A:  Aggressive (enables OS, version, scripts, traceroute)
# -p-: All ports
# -T4: Fast timing
```

### Web Server Enumeration

```bash
sudo nmap -p 80,443,8080,8443 --script http-enum,http-title,http-headers <target>
```

### SMB Enumeration

```bash
sudo nmap -p 445 --script smb-os-discovery,smb-enum-shares,smb-enum-users <target>
```

### Vulnerability Assessment

```bash
sudo nmap -sV --script vuln <target>
```

---

## Firewall/IDS Evasion

### Fragmentation

```bash
# Fragment packets
sudo nmap -f <target>

# Specific MTU
sudo nmap --mtu 24 <target>
```

### Decoy Scans

```bash
# Use decoy IPs
sudo nmap -D RND:10 <target>

# Specific decoys
sudo nmap -D decoy1,decoy2,ME,decoy3 <target>
```

### Source Port Manipulation

```bash
# Use source port 53 (DNS)
sudo nmap --source-port 53 <target>
```

### Randomize Host Order

```bash
nmap --randomize-hosts <target range>
```

### Idle/Zombie Scan

```bash
# Use zombie host
sudo nmap -sI <zombie_ip> <target>
```

---

## Hands-On Exercises

### Exercise 1: Basic Scanning

```bash
# 1. Discover live hosts on your network
sudo nmap -sn 192.168.1.0/24

# 2. Quick scan of a target
nmap -F <target_ip>

# 3. Full port scan
sudo nmap -p- <target_ip>

# 4. Service version detection
sudo nmap -sV <target_ip>
```

### Exercise 2: Advanced Scanning

```bash
# 1. Stealth SYN scan with version detection
sudo nmap -sS -sV -T4 <target_ip>

# 2. OS detection
sudo nmap -O <target_ip>

# 3. Aggressive scan
sudo nmap -A <target_ip>

# 4. UDP scan of common ports
sudo nmap -sU --top-ports 20 <target_ip>
```

### Exercise 3: NSE Scripts

```bash
# 1. Default scripts
nmap -sC <target_ip>

# 2. Vulnerability scan
nmap --script vuln <target_ip>

# 3. HTTP enumeration
nmap --script http-enum -p 80 <target_ip>

# 4. SMB enumeration
nmap --script smb-enum-shares -p 445 <target_ip>
```

### Exercise 4: Real-World Scenario

**Scenario:** You're pentesting a new network.

```bash
# Step 1: Network discovery
sudo nmap -sn 10.0.0.0/24 -oA discovery

# Step 2: Extract live IPs
grep "Up" discovery.gnmap | cut -d " " -f 2 > live_hosts.txt

# Step 3: Quick port scan
sudo nmap -iL live_hosts.txt -F -oA quick_scan

# Step 4: Comprehensive scan on interesting hosts
sudo nmap -sS -sV -O -p- -T4 <interesting_ip> -oA deep_scan

# Step 5: Vulnerability assessment
sudo nmap --script vuln <interesting_ip> -oA vuln_scan
```

---

## Interpreting Results

### Identifying Attack Vectors

```
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 2.3.4
```
**Action:** Search for vsftpd 2.3.4 exploits (famous backdoor!)

```
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 7.2p2
```
**Action:** Check for user enumeration, weak ciphers

```
PORT     STATE SERVICE     VERSION
3306/tcp open  mysql       MySQL 5.5.47
```
**Action:** Test default credentials, SQL injection

### Red Flags

- **FTP on port 21** with anonymous login
- **Telnet on port 23** (unencrypted)
- **SMB with guest access**
- **Outdated software versions**
- **Default credentials**
- **Unnecessary services running**

---

## Other Scanning Tools

### Masscan

**Extremely fast port scanner**

```bash
# Scan entire internet for port 80 (don't actually do this!)
masscan 0.0.0.0/0 -p80

# Fast scan of network
masscan 192.168.1.0/24 -p0-65535 --rate=10000
```

### Unicornscan

```bash
unicornscan -mT <target>:1-65535
```

### Netcat (Manual Port Checking)

```bash
# Check if port is open
nc -zv <target> 80

# Connect to port
nc <target> 80
```

---

## Best Practices

1. **Always get authorization** before scanning
2. **Start with passive reconnaissance** (OSINT)
3. **Use appropriate timing** (don't DoS the target)
4. **Save all output** for reporting
5. **Understand what you're scanning** (read the script descriptions)
6. **Verify results** (false positives happen)
7. **Respect rate limits** and network capacity

---

## Legal and Ethical Considerations

### Only Scan Authorized Targets

- Your own systems
- Client-authorized systems (in writing!)
- Bug bounty programs (within scope)
- Lab environments (HTB, THM, VulnHub)

### Scanning Can Be Considered:

- Network reconnaissance (illegal without permission)
- Attempted unauthorized access
- DoS if too aggressive

**Always have written authorization!**

---

## Key Takeaways

1. Nmap is the industry standard for port scanning
2. Different scan types for different scenarios
3. NSE scripts provide powerful enumeration capabilities
4. Service version detection reveals vulnerabilities
5. Proper timing prevents detection and DoS
6. Always save scan results for reporting
7. Authorization is mandatory before scanning

---

## Next Lesson
**Lesson 2.3: Protocol Analysis & Exploitation** - Deep dive into HTTP, FTP, SMB, DNS, and other protocols.
