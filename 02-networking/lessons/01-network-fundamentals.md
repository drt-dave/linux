# Lesson 2.1: Network Fundamentals & OSI Model

## Objective
Understand the foundational networking concepts, OSI model, TCP/IP stack, and IP addressing essential for network penetration testing.

---

## The OSI Model (7 Layers)

The OSI (Open Systems Interconnection) model is a conceptual framework for understanding network communications.

```
Layer 7: APPLICATION   - HTTP, FTP, DNS, SMTP (What the user sees)
Layer 6: PRESENTATION  - Encryption, compression, formatting
Layer 5: SESSION       - Session establishment, maintenance
Layer 4: TRANSPORT     - TCP, UDP (Port numbers, reliability)
Layer 3: NETWORK       - IP, ICMP, routing (IP addresses)
Layer 2: DATA LINK     - Ethernet, MAC addresses, switches
Layer 1: PHYSICAL      - Cables, signals, hubs
```

### Mnemonic
**Please Do Not Throw Sausage Pizza Away**
(Physical, Data Link, Network, Transport, Session, Presentation, Application)

---

## TCP/IP Model (4 Layers)

More practical model used in real networks:

```
Layer 4: APPLICATION   - HTTP, FTP, SSH, DNS (OSI L5-L7)
Layer 3: TRANSPORT     - TCP, UDP
Layer 2: INTERNET      - IP, ICMP, routing
Layer 1: NETWORK ACCESS - Ethernet, WiFi (OSI L1-L2)
```

---

## Layer 3: Network Layer (IP Addressing)

### IPv4 Address Structure

```
192.168.1.100
│   │   │ │
│   │   │ └─ Host ID
│   │   └─── Subnet
│   └─────── Network
└─────────── Class

Binary: 11000000.10101000.00000001.01100100
```

### IP Address Classes (Historical)

```
Class A: 1.0.0.0     - 126.255.255.255  (8 bits network)  /8
Class B: 128.0.0.0   - 191.255.255.255  (16 bits network) /16
Class C: 192.0.0.0   - 223.255.255.255  (24 bits network) /24
Class D: 224.0.0.0   - 239.255.255.255  (Multicast)
Class E: 240.0.0.0   - 255.255.255.255  (Reserved)
```

### Private IP Ranges (RFC 1918)

```
10.0.0.0    - 10.255.255.255   (10.0.0.0/8)     - 16 million IPs
172.16.0.0  - 172.31.255.255   (172.16.0.0/12)  - 1 million IPs
192.168.0.0 - 192.168.255.255  (192.168.0.0/16) - 65,536 IPs
```

**Hacking Note:** These ranges are non-routable on the internet. If you see these during pentesting, you're on an internal network.

### Special IP Addresses

```
0.0.0.0         - Default route / "any" address
127.0.0.1       - Localhost / loopback
255.255.255.255 - Broadcast address
169.254.x.x     - APIPA (Automatic Private IP) - DHCP failure
```

---

## Subnetting

### Subnet Mask

Determines which portion is network vs host:

```
IP:      192.168.1.100
Mask:    255.255.255.0
Binary:  11111111.11111111.11111111.00000000
         └─────────Network──────────┘└─Host─┘
```

### CIDR Notation

```
/24 = 255.255.255.0
/16 = 255.255.0.0
/8  = 255.0.0.0

Example: 192.168.1.0/24
```

### Calculating Network Size

```
/24 = 2^(32-24) = 2^8  = 256 addresses (254 usable)
/25 = 2^7  = 128 addresses (126 usable)
/26 = 2^6  = 64 addresses  (62 usable)
/27 = 2^5  = 32 addresses  (30 usable)
/28 = 2^4  = 16 addresses  (14 usable)
/29 = 2^3  = 8 addresses   (6 usable)
/30 = 2^2  = 4 addresses   (2 usable - point-to-point)
```

**Why -2?** Network address and broadcast address are not usable.

### Subnetting Example

**Network:** 192.168.1.0/24
**Requirement:** 4 subnets

```
Original:    192.168.1.0/24  (254 hosts)
Borrow 2 bits for subnets (2^2 = 4 subnets)
New mask:    /26

Subnets:
1. 192.168.1.0/26    (192.168.1.1   - 192.168.1.62)
2. 192.168.1.64/26   (192.168.1.65  - 192.168.1.126)
3. 192.168.1.128/26  (192.168.1.129 - 192.168.1.190)
4. 192.168.1.192/26  (192.168.1.193 - 192.168.1.254)
```

**Pentesting Use:** Understanding subnetting helps you identify network boundaries and plan your scanning strategy.

---

## Layer 4: Transport Layer

### TCP (Transmission Control Protocol)

**Connection-oriented, reliable**

#### TCP Three-Way Handshake

```
Client                    Server
  │                         │
  ├─── SYN ──────────────>  │  (Client initiates)
  │                         │
  │  <──── SYN-ACK ────────┤  (Server responds)
  │                         │
  ├─── ACK ──────────────>  │  (Connection established)
  │                         │
  ├──── DATA ────────────>  │
  │  <──── ACK ────────────┤
```

**Flags:**
- **SYN** - Synchronize (initiate connection)
- **ACK** - Acknowledgment
- **FIN** - Finish (close connection)
- **RST** - Reset (abrupt close)
- **PSH** - Push (send data immediately)
- **URG** - Urgent

**Hacking Use:** Understanding TCP flags is critical for:
- Port scanning (SYN scan = stealth)
- Detecting filtered ports
- Session hijacking
- TCP reset attacks

### UDP (User Datagram Protocol)

**Connectionless, unreliable, fast**

```
Client                    Server
  │                         │
  ├──── DATA ────────────>  │  (No handshake)
  │                         │
```

**Used by:** DNS, DHCP, TFTP, SNMP, VoIP

**Pentesting Note:** UDP scanning is slower and less reliable, but critical services use UDP.

### Port Numbers

```
0-1023     Well-known ports (require root)
1024-49151 Registered ports
49152-65535 Dynamic/ephemeral ports

Common Well-Known Ports:
21  - FTP
22  - SSH
23  - Telnet
25  - SMTP
53  - DNS
80  - HTTP
110 - POP3
143 - IMAP
443 - HTTPS
445 - SMB
3306 - MySQL
3389 - RDP
```

---

## Layer 2: Data Link (MAC Addresses)

### MAC Address Structure

```
00:1A:2B:3C:4D:5E
│  │  │  └───────── Device specific (NIC ID)
│  │  └────────────
│  └─────────────── Manufacturer (OUI)
└────────────────── Organizationally Unique Identifier

Example:
00:0C:29:XX:XX:XX = VMware
08:00:27:XX:XX:XX = VirtualBox
DC:A6:32:XX:XX:XX = Raspberry Pi
```

**Hacking Use:**
- Identify device types in network
- ARP spoofing uses MAC addresses
- MAC filtering bypass

### ARP (Address Resolution Protocol)

Translates IP addresses to MAC addresses on local network.

```
Who has 192.168.1.1? Tell 192.168.1.100

192.168.1.1 is at 00:1A:2B:3C:4D:5E
```

**ARP Cache:**
```bash
arp -a              # View ARP cache
ip neigh            # Alternative command
```

**ARP Spoofing Attack:**
Attacker sends fake ARP responses to redirect traffic.

---

## Network Devices

### Hub (Layer 1)
- Broadcasts to all ports
- No intelligence
- Collision domain issues
- **Security:** Easy to sniff traffic

### Switch (Layer 2)
- Forwards based on MAC address
- Creates separate collision domains
- Maintains MAC address table
- **Security:** MAC flooding can turn it into hub

### Router (Layer 3)
- Routes between networks
- Uses IP addresses
- Network Address Translation (NAT)
- Firewall capabilities

### Firewall
- Filters traffic based on rules
- Can operate at multiple layers
- Stateful vs stateless

---

## ICMP (Internet Control Message Protocol)

Used for diagnostics and error reporting.

### Ping (ICMP Echo Request/Reply)

```bash
ping 192.168.1.1
ping -c 4 192.168.1.1    # Send 4 packets
ping -s 1000 192.168.1.1 # Larger packet size
```

**ICMP Types:**
```
Type 0  - Echo Reply (pong)
Type 3  - Destination Unreachable
Type 5  - Redirect
Type 8  - Echo Request (ping)
Type 11 - Time Exceeded (traceroute)
```

**Hacking Use:**
- Host discovery
- Network mapping
- Firewall detection
- Ping sweep for live hosts
- ICMP tunneling (covert channel)

### Traceroute

Shows path to destination:
```bash
traceroute google.com
traceroute -I google.com  # Use ICMP instead of UDP
```

---

## DNS (Domain Name System)

Translates domain names to IP addresses.

### DNS Record Types

```
A      - IPv4 address
AAAA   - IPv6 address
CNAME  - Canonical name (alias)
MX     - Mail server
NS     - Name server
TXT    - Text records (SPF, DKIM, etc.)
SOA    - Start of Authority
PTR    - Reverse DNS lookup
```

### DNS Query Example

```bash
dig google.com           # Full DNS query
dig google.com A         # Only A records
dig google.com MX        # Mail servers
dig @8.8.8.8 google.com  # Specific DNS server
nslookup google.com      # Alternative tool
host google.com          # Simple lookup
```

**Hacking Use:**
- Subdomain enumeration
- Zone transfer attempts
- DNS cache poisoning
- Identifying mail servers, name servers
- Reconnaissance without touching target

---

## NAT (Network Address Translation)

Translates private IPs to public IPs.

```
Internal Network:        Router:           Internet:
192.168.1.100:50000  ->  203.0.113.5:50000  ->  8.8.8.8:53
192.168.1.101:50001  ->  203.0.113.5:50001  ->  1.1.1.1:443
```

**Types:**
- **Static NAT** - One-to-one mapping
- **Dynamic NAT** - Pool of public IPs
- **PAT** (Port Address Translation) - Many-to-one with different ports

**Pentesting Impact:**
- Internal IPs not directly accessible from internet
- Port forwarding exposes internal services
- NAT traversal techniques needed for reverse shells

---

## Hands-On Exercises

### Exercise 1: IP Addressing Practice
```bash
# Find your IP address
ip addr show
ifconfig

# Find your default gateway
ip route | grep default
route -n

# Find your DNS servers
cat /etc/resolv.conf
```

### Exercise 2: Subnetting Calculations
Calculate for 172.16.50.0/22:
1. Subnet mask in decimal?
2. Network address?
3. Broadcast address?
4. First usable IP?
5. Last usable IP?
6. Total usable hosts?

**Answers:**
1. 255.255.252.0
2. 172.16.48.0
3. 172.16.51.255
4. 172.16.48.1
5. 172.16.51.254
6. 1022

### Exercise 3: ARP Analysis
```bash
# View ARP cache
arp -a
ip neigh

# Ping a host to populate ARP
ping -c 1 192.168.1.1

# Check ARP cache again
arp -a

# Clear ARP cache (requires root)
ip neigh flush all
```

### Exercise 4: ICMP Diagnostics
```bash
# Ping local gateway
ping -c 4 <gateway_ip>

# Ping external host
ping -c 4 8.8.8.8

# Traceroute to destination
traceroute google.com

# Detect ping blocking
ping -c 1 <target> || echo "ICMP blocked or host down"
```

### Exercise 5: DNS Enumeration
```bash
# Basic DNS lookup
dig google.com

# Get MX records
dig google.com MX

# Get all records
dig google.com ANY

# Reverse DNS lookup
dig -x 8.8.8.8

# Query specific DNS server
dig @1.1.1.1 google.com
```

---

## Common Network Troubleshooting

### Connectivity Issues

```bash
# Check interface status
ip link show

# Check IP configuration
ip addr show

# Check routing table
ip route

# Test connectivity
ping <gateway>
ping 8.8.8.8       # Test internet
ping google.com    # Test DNS

# Trace network path
traceroute <destination>
mtr <destination>  # Better than traceroute
```

### Port Testing

```bash
# Test if port is open
nc -zv <ip> <port>
telnet <ip> <port>

# Check listening ports locally
ss -tuln
netstat -tuln
```

---

## Security Implications

### Attack Surface

Every open port is a potential entry point:
```bash
# Identify your attack surface
ss -tuln | grep LISTEN
```

### Information Disclosure

Network information reveals:
- Operating system (TTL values, TCP fingerprinting)
- Network topology
- Running services
- Potential vulnerabilities

### Defense Considerations

- Close unnecessary ports
- Use firewalls
- Disable ICMP if not needed (but breaks diagnostics)
- Segment networks
- Monitor ARP cache for spoofing
- Use VLANs for network isolation

---

## Key Takeaways

1. OSI and TCP/IP models provide framework for understanding networks
2. IP addressing and subnetting are fundamental for network pentesting
3. TCP three-way handshake is essential for port scanning
4. MAC addresses and ARP are exploitable at Layer 2
5. ICMP, DNS, and NAT are common reconnaissance targets
6. Understanding protocols helps identify attack vectors

---

## Next Lesson
**Lesson 2.2: Network Scanning & Enumeration** - Learn Nmap, port scanning techniques, and service enumeration.
