# Module 2: Networking for Ethical Hacking

## Overview
This module provides comprehensive networking knowledge essential for penetration testing. You'll learn network protocols, scanning techniques, packet analysis, and how to perform man-in-the-middle attacks.

## Module Objectives
- Understand OSI model and TCP/IP stack
- Master network scanning and enumeration
- Analyze network traffic with packet capture
- Perform ARP spoofing and MITM attacks
- Enumerate network services
- Understand DNS, HTTP, FTP, SMB protocols
- Learn subnetting and IP addressing

## Lessons

### 2.1 - Network Fundamentals & OSI Model
- OSI 7-layer model
- TCP/IP stack
- IP addressing and subnetting
- Network protocols overview
- Understanding packets and frames

**Location:** `lessons/01-network-fundamentals.md`

### 2.2 - Network Scanning & Enumeration
- Port scanning techniques
- Nmap mastery
- Service version detection
- OS fingerprinting
- NSE (Nmap Scripting Engine)
- Network discovery techniques

**Location:** `lessons/02-network-scanning.md`

### 2.3 - Protocol Analysis & Exploitation
- HTTP/HTTPS deep dive
- FTP exploitation
- SMB enumeration and attacks
- DNS reconnaissance
- SNMP exploitation
- SMTP/POP3/IMAP testing

**Location:** `lessons/03-protocol-exploitation.md`

### 2.4 - Man-in-the-Middle Attacks
- ARP spoofing fundamentals
- Network traffic interception
- SSL stripping
- DNS spoofing
- Session hijacking
- Wireshark packet analysis

**Location:** `lessons/04-mitm-attacks.md`

## Practice Scripts

### 1. Advanced Network Scanner
**File:** `scripts/advanced_port_scanner.sh`

Comprehensive port scanning tool with service detection:
- Multiple scan types (SYN, connect, UDP)
- Service version enumeration
- Common vulnerability checks
- Banner grabbing
- Output formatting

**Usage:**
```bash
./scripts/advanced_port_scanner.sh <target_ip>
```

---

### 2. ARP Scanner & Network Mapper
**File:** `scripts/arp_scanner.sh`

Discover all hosts on local network:
- ARP-based host discovery
- MAC address vendor lookup
- Network topology mapping
- Live host enumeration
- DHCP server detection

**Usage:**
```bash
./scripts/arp_scanner.sh
```

---

### 3. DNS Enumeration Tool
**File:** `scripts/dns_enum.sh`

Comprehensive DNS reconnaissance:
- Subdomain enumeration
- Zone transfer attempts
- DNS record gathering (A, AAAA, MX, TXT, NS)
- Reverse DNS lookups
- DNS cache snooping

**Usage:**
```bash
./scripts/dns_enum.sh <domain>
```

---

### 4. Service Enumeration Script
**File:** `scripts/service_enum.sh`

Deep service enumeration and fingerprinting:
- SMB share enumeration
- FTP anonymous login testing
- HTTP/HTTPS service detection
- SSH version detection
- Database service discovery
- Common default credentials testing

**Usage:**
```bash
./scripts/service_enum.sh <target_ip>
```

---

### 5. Packet Analyzer
**File:** `scripts/packet_analyzer.sh`

Network traffic analysis wrapper:
- Interface monitoring
- Protocol statistics
- Connection tracking
- Suspicious traffic detection
- Capture file analysis

**Usage:**
```bash
./scripts/packet_analyzer.sh <interface>
```

---

## Hands-On Exercises

### Exercise 1: Network Discovery
1. Identify your network range with `ip addr` or `ifconfig`
2. Perform ping sweep to find live hosts
3. Scan common ports on discovered hosts
4. Identify operating systems using TTL values
5. Create network diagram of discovered hosts

### Exercise 2: Port Scanning Mastery
1. Perform full TCP scan: `nmap -p- <target>`
2. Service version scan: `nmap -sV <target>`
3. OS detection: `nmap -O <target>`
4. Aggressive scan: `nmap -A <target>`
5. Stealth SYN scan: `nmap -sS <target>`
6. UDP scan: `nmap -sU -p 53,161,500 <target>`

### Exercise 3: Service Enumeration
1. Enumerate SMB shares: `smbclient -L //<target> -N`
2. Test FTP anonymous login: `ftp <target>`
3. Banner grab HTTP: `nc <target> 80` then `GET / HTTP/1.1`
4. Enumerate DNS: `dig @<target> <domain> ANY`
5. SNMP enumeration: `snmpwalk -v2c -c public <target>`

### Exercise 4: Traffic Analysis
1. Install Wireshark if not present
2. Capture HTTP traffic
3. Follow TCP streams
4. Export captured credentials
5. Identify protocols in capture file
6. Find suspicious connections

### Exercise 5: ARP Spoofing (Lab Only!)
1. Identify gateway and target IP
2. Enable IP forwarding: `echo 1 > /proc/sys/net/ipv4/ip_forward`
3. Start ARP spoofing (use arpspoof or script)
4. Capture traffic with tcpdump
5. Analyze intercepted traffic
6. Cleanup and restore ARP tables

---

## Additional Practice

### TryHackMe Rooms
- Network Services (SMB, Telnet, FTP)
- Network Services 2 (NFS, SMTP, MySQL)
- Nmap (Complete walkthrough)
- Wireshark 101
- Protocols and Servers

### HackTheBox Machines
- Lame (Easy - SMB exploitation)
- Legacy (Easy - MS08-067)
- Blue (Easy - EternalBlue)
- Netmon (Easy - SNMP enumeration)

---

## Quick Reference

### Nmap Scan Types
```bash
# Basic scans
nmap -sT <target>          # TCP Connect scan
nmap -sS <target>          # SYN stealth scan
nmap -sU <target>          # UDP scan
nmap -sA <target>          # ACK scan
nmap -sN <target>          # NULL scan

# Service/OS detection
nmap -sV <target>          # Service version
nmap -O <target>           # OS detection
nmap -A <target>           # Aggressive (OS, version, scripts, traceroute)

# Port specifications
nmap -p 80,443 <target>    # Specific ports
nmap -p 1-1000 <target>    # Port range
nmap -p- <target>          # All 65535 ports
nmap --top-ports 100 <target>  # Top 100 common ports

# Timing and performance
nmap -T4 <target>          # Faster timing
nmap -T0 <target>          # Paranoid (slowest, stealthiest)
nmap --max-rate 100 <target>   # Max packets per second

# NSE scripts
nmap --script vuln <target>         # Vulnerability scripts
nmap --script default <target>      # Default safe scripts
nmap --script smb-enum-shares <target>  # Specific script
```

### Common Network Commands
```bash
# Interface information
ip addr                    # Show IP addresses
ifconfig                   # Alternative to ip addr
ip route                   # Show routing table

# Network connections
ss -tuln                   # Active connections
netstat -tuln              # Alternative to ss
lsof -i                    # Open network files

# DNS queries
dig <domain>               # DNS lookup
nslookup <domain>          # Alternative DNS lookup
host <domain>              # Simple DNS lookup
whois <domain>             # Domain registration info

# Packet capture
tcpdump -i eth0            # Capture on interface
tcpdump -w capture.pcap    # Write to file
tcpdump -r capture.pcap    # Read from file
tcpdump 'port 80'          # Filter by port

# File transfers
nc -lvnp 8000 < file       # Send file
nc <ip> 8000 > file        # Receive file
python3 -m http.server     # Simple HTTP server
```

### Protocol Default Ports
```
20/21  - FTP
22     - SSH
23     - Telnet
25     - SMTP
53     - DNS
80     - HTTP
110    - POP3
143    - IMAP
443    - HTTPS
445    - SMB
3306   - MySQL
3389   - RDP
5432   - PostgreSQL
5900   - VNC
8080   - HTTP Alternate
```

### Subnetting Quick Reference
```
/24 = 255.255.255.0   = 254 hosts
/25 = 255.255.255.128 = 126 hosts
/26 = 255.255.255.192 = 62 hosts
/27 = 255.255.255.224 = 30 hosts
/28 = 255.255.255.240 = 14 hosts
/29 = 255.255.255.248 = 6 hosts
/30 = 255.255.255.252 = 2 hosts
```

---

## Resources

- **Nmap Official Guide:** https://nmap.org/book/
- **Wireshark Documentation:** https://www.wireshark.org/docs/
- **TCP/IP Illustrated:** Classic networking book series
- **RFC Documents:** https://www.rfc-editor.org/ (Protocol specifications)
- **Subnet Calculator:** https://www.subnet-calculator.com/
- **HacKTricks Pentesting Network:** https://book.hacktricks.xyz/network-services-pentesting

---

## Progress Checklist

- [ ] Completed Lesson 2.1 - Network Fundamentals
- [ ] Completed Lesson 2.2 - Network Scanning
- [ ] Completed Lesson 2.3 - Protocol Exploitation
- [ ] Completed Lesson 2.4 - MITM Attacks
- [ ] Performed network discovery on local network
- [ ] Completed full Nmap scan of target
- [ ] Enumerated SMB shares successfully
- [ ] Captured and analyzed network traffic
- [ ] Performed ARP scan successfully
- [ ] DNS enumeration completed
- [ ] Executed all practice scripts
- [ ] Completed all hands-on exercises

---

**Next Module:** [03-Web Security →](../03-web-security/)
