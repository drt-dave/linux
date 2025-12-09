# Networking Concepts Tutorial
## From Fundamentals to Web Application Networking

---

## Table of Contents
1. [Networking Fundamentals](#networking-fundamentals)
2. [OSI and TCP/IP Models](#osi-and-tcpip-models)
3. [IP Addressing and Subnetting](#ip-addressing-and-subnetting)
4. [Transport Protocols: TCP and UDP](#transport-protocols-tcp-and-udp)
5. [DNS and Name Resolution](#dns-and-name-resolution)
6. [HTTP/HTTPS and Web Traffic](#httphttps-and-web-traffic)
7. [Network Configuration in Linux](#network-configuration-in-linux)
8. [Firewalls and Security](#firewalls-and-security)
9. [Network Troubleshooting](#network-troubleshooting)

---

## Networking Fundamentals

### What is a Network?

A network is a collection of devices connected together to share resources and communicate. Key concepts:

- **Host**: Any device on a network (computer, phone, server)
- **Client**: Device requesting services
- **Server**: Device providing services
- **Protocol**: Rules for communication
- **Packet**: Unit of data transmitted over a network

### Network Types

```
┌─────────────────────────────────────────┐
│ PAN (Personal Area Network)            │  Bluetooth, USB
├─────────────────────────────────────────┤
│ LAN (Local Area Network)               │  Home, Office
├─────────────────────────────────────────┤
│ MAN (Metropolitan Area Network)        │  City-wide
├─────────────────────────────────────────┤
│ WAN (Wide Area Network)                │  Internet
└─────────────────────────────────────────┘
```

**Practical Example**: Identify your network
```bash
# View network interfaces
ip addr show
# or older command
ifconfig

# Common interfaces:
# lo - Loopback (127.0.0.1)
# eth0 - Ethernet
# wlan0 - Wireless
# docker0 - Docker bridge

# View your IP address
hostname -I

# Check default gateway (router)
ip route show
# Output: default via 192.168.1.1 dev eth0
```

---

## OSI and TCP/IP Models

### OSI Model (7 Layers)

The OSI model describes how data travels from one computer to another:

```
┌─────────────────────────────────────────────────────────────┐
│ Layer 7: Application  │ HTTP, FTP, SSH, DNS, SMTP          │
├─────────────────────────────────────────────────────────────┤
│ Layer 6: Presentation │ SSL/TLS, Encryption, Compression   │
├─────────────────────────────────────────────────────────────┤
│ Layer 5: Session      │ Session Management, Auth           │
├─────────────────────────────────────────────────────────────┤
│ Layer 4: Transport    │ TCP, UDP, Ports                    │
├─────────────────────────────────────────────────────────────┤
│ Layer 3: Network      │ IP, Routing, ICMP                  │
├─────────────────────────────────────────────────────────────┤
│ Layer 2: Data Link    │ MAC addresses, Switches, Ethernet  │
├─────────────────────────────────────────────────────────────┤
│ Layer 1: Physical     │ Cables, Signals, Bits              │
└─────────────────────────────────────────────────────────────┘
```

### TCP/IP Model (4 Layers)

The practical implementation used by the Internet:

```
┌──────────────────────────────────────────┐
│ Application Layer                        │  HTTP, SSH, FTP, DNS
│ (OSI 5-7)                                │
├──────────────────────────────────────────┤
│ Transport Layer                          │  TCP, UDP
│ (OSI 4)                                  │
├──────────────────────────────────────────┤
│ Internet Layer                           │  IP, ICMP, ARP
│ (OSI 3)                                  │
├──────────────────────────────────────────┤
│ Network Access Layer                     │  Ethernet, WiFi
│ (OSI 1-2)                                │
└──────────────────────────────────────────┘
```

### Data Encapsulation

As data moves down the layers, each layer adds a header:

```
Application:  [Data]
Transport:    [TCP Header][Data]
Internet:     [IP Header][TCP Header][Data]
Network:      [Ethernet Header][IP Header][TCP Header][Data][Ethernet Trailer]
              └────────────────── Packet ──────────────────┘
```

**Practical Example**: View packet structure with tcpdump
```bash
# Capture HTTP traffic
sudo tcpdump -i eth0 -n port 80 -A

# Capture and save to file
sudo tcpdump -i eth0 -w capture.pcap

# Read captured file
tcpdump -r capture.pcap

# Analyze with Wireshark (GUI)
wireshark capture.pcap
```

---

## IP Addressing and Subnetting

### IPv4 Addresses

An IPv4 address is 32 bits divided into 4 octets:

```
192.168.1.100
└─┬─┘└─┬─┘└┬┘└─┬─┘
  8    8  8   8  bits = 32 bits total

Binary: 11000000.10101000.00000001.01100100
```

### IP Address Classes (Historical)

```
Class A: 0.0.0.0     to 127.255.255.255  (16M hosts)
Class B: 128.0.0.0   to 191.255.255.255  (65K hosts)
Class C: 192.0.0.0   to 223.255.255.255  (254 hosts)
Class D: 224.0.0.0   to 239.255.255.255  (Multicast)
Class E: 240.0.0.0   to 255.255.255.255  (Reserved)
```

### Private IP Ranges (RFC 1918)

```
10.0.0.0      - 10.255.255.255     (10/8)
172.16.0.0    - 172.31.255.255     (172.16/12)
192.168.0.0   - 192.168.255.255    (192.168/16)
```

### CIDR Notation

CIDR (Classless Inter-Domain Routing) uses /prefix to indicate network size:

```
192.168.1.0/24
           └─┬┘
             └─ 24 bits for network, 8 bits for hosts

/24 = 255.255.255.0   → 254 usable hosts
/16 = 255.255.0.0     → 65,534 usable hosts
/8  = 255.0.0.0       → 16,777,214 usable hosts
```

**Subnet Calculation**:

```bash
# Install network calculator
sudo apt install ipcalc

# Calculate subnet
ipcalc 192.168.1.0/24

# Output:
# Address:   192.168.1.0          11000000.10101000.00000001. 00000000
# Netmask:   255.255.255.0 = 24   11111111.11111111.11111111. 00000000
# Network:   192.168.1.0/24       11000000.10101000.00000001. 00000000
# HostMin:   192.168.1.1          11000000.10101000.00000001. 00000001
# HostMax:   192.168.1.254        11000000.10101000.00000001. 11111110
# Broadcast: 192.168.1.255        11000000.10101000.00000001. 11111111
# Hosts/Net: 254
```

### Special IP Addresses

```
0.0.0.0         Default route, unspecified
127.0.0.1       Loopback (localhost)
169.254.0.0/16  Link-local (APIPA)
255.255.255.255 Broadcast (all hosts)
```

**Practical Examples**:

```bash
# Show IP configuration
ip addr show

# Add IP address to interface
sudo ip addr add 192.168.1.100/24 dev eth0

# Remove IP address
sudo ip addr del 192.168.1.100/24 dev eth0

# Set interface up/down
sudo ip link set eth0 up
sudo ip link set eth0 down

# Ping local network
ping 192.168.1.1
ping -c 4 google.com      # Send only 4 packets
```

---

## Transport Protocols: TCP and UDP

### TCP (Transmission Control Protocol)

**Characteristics**:
- Connection-oriented (three-way handshake)
- Reliable (guarantees delivery, order)
- Flow control and congestion control
- Slower but ensures data integrity
- Used for: HTTP, HTTPS, SSH, FTP, SMTP

**Three-Way Handshake**:

```
Client                    Server
  │                         │
  │─────── SYN ────────────>│  1. Client: "Let's connect"
  │                         │
  │<────── SYN-ACK ─────────│  2. Server: "OK, ready"
  │                         │
  │─────── ACK ────────────>│  3. Client: "Confirmed"
  │                         │
  │    Connected!           │
```

**Connection Termination**:

```
Client                    Server
  │                         │
  │─────── FIN ────────────>│  1. Client: "Done sending"
  │                         │
  │<────── ACK ─────────────│  2. Server: "Acknowledged"
  │                         │
  │<────── FIN ─────────────│  3. Server: "I'm done too"
  │                         │
  │─────── ACK ────────────>│  4. Client: "Goodbye"
```

### UDP (User Datagram Protocol)

**Characteristics**:
- Connectionless (no handshake)
- Unreliable (no delivery guarantee)
- No flow control
- Faster, lower overhead
- Used for: DNS, DHCP, VoIP, streaming, gaming

**TCP vs UDP Comparison**:

```
┌────────────────┬─────────────────┬─────────────────┐
│ Feature        │ TCP             │ UDP             │
├────────────────┼─────────────────┼─────────────────┤
│ Connection     │ Yes             │ No              │
│ Reliability    │ Guaranteed      │ Best effort     │
│ Ordering       │ Yes             │ No              │
│ Speed          │ Slower          │ Faster          │
│ Overhead       │ Higher          │ Lower           │
│ Use Case       │ Web, Email      │ Streaming, DNS  │
└────────────────┴─────────────────┴─────────────────┘
```

### Ports

Ports identify specific applications/services (0-65535):

```
Well-Known Ports (0-1023):
  20/21   FTP
  22      SSH
  23      Telnet
  25      SMTP
  53      DNS
  80      HTTP
  110     POP3
  143     IMAP
  443     HTTPS
  3306    MySQL
  5432    PostgreSQL
  6379    Redis
  27017   MongoDB

Registered Ports (1024-49151):
  3000    Node.js/React dev server
  3001    Common API port
  5000    Flask default
  8080    HTTP alternate
  8443    HTTPS alternate

Dynamic/Private (49152-65535):
  Ephemeral ports for client connections
```

**Practical Examples**:

```bash
# Show listening ports
sudo ss -tlnp
# t = TCP, l = listening, n = numeric, p = processes

# Output:
# State    Recv-Q Send-Q Local Address:Port  Peer Address:Port
# LISTEN   0      128    0.0.0.0:22          0.0.0.0:*     users:(("sshd",pid=1234))
# LISTEN   0      128    0.0.0.0:80          0.0.0.0:*     users:(("nginx",pid=5678))

# Older command
sudo netstat -tlnp

# Show all connections
ss -tunap
# u = UDP

# Check if port is open
nc -zv localhost 80
# z = scan, v = verbose

# Listen on port (simple server)
nc -l 8080

# Connect to port (from another terminal)
nc localhost 8080
# Type messages to send
```

---

## DNS and Name Resolution

### What is DNS?

DNS (Domain Name System) translates human-readable domain names to IP addresses:

```
www.example.com → 93.184.216.34
```

### DNS Hierarchy

```
                         . (Root)
                          │
          ┌───────────────┼───────────────┐
        .com            .org            .net
          │
    example.com
          │
     www.example.com
```

### DNS Record Types

```
A       IPv4 address              example.com → 93.184.216.34
AAAA    IPv6 address              example.com → 2606:2800:220:1:248:1893:25c8:1946
CNAME   Canonical name (alias)    www.example.com → example.com
MX      Mail server               example.com → mail.example.com
TXT     Text record               SPF, DKIM, verification
NS      Name server               example.com → ns1.example.com
PTR     Reverse DNS               34.216.184.93 → example.com
```

### Name Resolution Process

```
1. Check local cache
2. Check /etc/hosts
3. Query DNS resolver (ISP or custom)
4. Resolver queries root servers
5. Resolver queries TLD servers (.com)
6. Resolver queries authoritative servers
7. Return IP to client
```

**Practical Examples**:

```bash
# Query DNS
nslookup google.com
dig google.com
host google.com

# Detailed DNS query
dig google.com +trace          # Show full resolution path
dig google.com ANY             # All record types
dig google.com MX              # Mail servers
dig @8.8.8.8 google.com        # Use specific DNS server

# DNS records for domain
dig example.com A              # IPv4
dig example.com AAAA           # IPv6
dig example.com TXT            # Text records

# Reverse DNS lookup
dig -x 8.8.8.8

# Check DNS propagation
dig +short google.com @8.8.8.8      # Google DNS
dig +short google.com @1.1.1.1      # Cloudflare DNS

# Local DNS cache (systemd-resolved)
systemd-resolve --status
systemd-resolve --flush-caches

# Edit local hosts file
sudo nano /etc/hosts
# Add: 127.0.0.1  myapp.local

# Test
ping myapp.local
```

### DNS Configuration in Linux

```bash
# View DNS settings
cat /etc/resolv.conf
# Output:
# nameserver 8.8.8.8
# nameserver 8.8.4.4

# Modern systems use systemd-resolved
resolvectl status

# Configure DNS with NetworkManager
nmcli connection modify eth0 ipv4.dns "8.8.8.8 8.8.4.4"
nmcli connection up eth0

# Or edit manually (persistent)
sudo nano /etc/systemd/resolved.conf
# [Resolve]
# DNS=8.8.8.8 8.8.4.4
# FallbackDNS=1.1.1.1 1.0.0.1

sudo systemctl restart systemd-resolved
```

---

## HTTP/HTTPS and Web Traffic

### HTTP Protocol

HTTP (HyperText Transfer Protocol) is the foundation of web communication:

**HTTP Request Structure**:
```
GET /api/users HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0
Accept: application/json
Authorization: Bearer token123

[Body - for POST/PUT]
```

**HTTP Response Structure**:
```
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 1234
Set-Cookie: session=abc123

{"users": [...]}
```

### HTTP Methods

```
GET     Retrieve resource          Safe, Idempotent
POST    Create resource            Not safe, Not idempotent
PUT     Update/replace resource    Not safe, Idempotent
PATCH   Partial update             Not safe, Not idempotent
DELETE  Remove resource            Not safe, Idempotent
HEAD    GET without body           Safe, Idempotent
OPTIONS Supported methods          Safe, Idempotent
```

### HTTP Status Codes

```
1xx Informational
  100 Continue

2xx Success
  200 OK
  201 Created
  204 No Content

3xx Redirection
  301 Moved Permanently
  302 Found (Temporary)
  304 Not Modified

4xx Client Error
  400 Bad Request
  401 Unauthorized
  403 Forbidden
  404 Not Found
  429 Too Many Requests

5xx Server Error
  500 Internal Server Error
  502 Bad Gateway
  503 Service Unavailable
  504 Gateway Timeout
```

### HTTPS and TLS

HTTPS = HTTP + TLS/SSL encryption

**TLS Handshake**:
```
1. Client Hello (supported ciphers)
2. Server Hello (chosen cipher, certificate)
3. Client verifies certificate
4. Key exchange (symmetric key established)
5. Encrypted communication begins
```

**Practical Examples**:

```bash
# Make HTTP request
curl http://example.com

# Make HTTPS request
curl https://example.com

# View response headers
curl -I https://example.com
# or
curl -i https://example.com

# Follow redirects
curl -L https://example.com

# POST JSON data
curl -X POST https://api.example.com/users \
  -H "Content-Type: application/json" \
  -d '{"name":"John","email":"john@example.com"}'

# Download file
curl -O https://example.com/file.zip
wget https://example.com/file.zip

# Test API endpoint
curl -X GET https://api.example.com/users \
  -H "Authorization: Bearer token123" \
  -H "Accept: application/json"

# View SSL certificate
openssl s_client -connect example.com:443 -showcerts

# Check SSL configuration
curl --verbose https://example.com 2>&1 | grep -i ssl
```

### React API Communication Example

```bash
# React app on localhost:3000 calling API on localhost:3001

# Check connection
curl http://localhost:3001/api/users

# Monitor network traffic
sudo tcpdump -i lo -n port 3001 -A

# View WebSocket connections (React DevTools)
ss -tn | grep :3000

# Test CORS
curl -H "Origin: http://localhost:3000" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: Content-Type" \
  -X OPTIONS \
  http://localhost:3001/api/users -v
```

---

## Network Configuration in Linux

### Viewing Network Configuration

```bash
# Modern command (ip)
ip addr show                   # Show IP addresses
ip link show                   # Show network interfaces
ip route show                  # Show routing table
ip neigh show                  # Show ARP cache

# Legacy commands (still work)
ifconfig
route -n
arp -a

# Network statistics
ss -s                          # Summary
netstat -i                     # Interface statistics
ip -s link                     # Interface stats with ip command
```

### Configuring Network Interfaces

**Temporary Configuration** (lost on reboot):
```bash
# Set IP address
sudo ip addr add 192.168.1.100/24 dev eth0

# Set default gateway
sudo ip route add default via 192.168.1.1

# Bring interface up/down
sudo ip link set eth0 up
sudo ip link set eth0 down

# Delete IP address
sudo ip addr del 192.168.1.100/24 dev eth0
```

**Permanent Configuration** (Ubuntu 22.04+):

Edit `/etc/netplan/01-netcfg.yaml`:
```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    eth0:
      addresses:
        - 192.168.1.100/24
      routes:
        - to: default
          via: 192.168.1.1
      nameservers:
        addresses:
          - 8.8.8.8
          - 8.8.4.4
```

Apply changes:
```bash
sudo netplan apply
```

**DHCP Configuration**:
```yaml
network:
  version: 2
  ethernets:
    eth0:
      dhcp4: true
```

### Network Manager (Desktop Systems)

```bash
# List connections
nmcli connection show

# Show device status
nmcli device status

# Connect to WiFi
nmcli device wifi list
nmcli device wifi connect "SSID" password "password"

# Modify connection
nmcli connection modify eth0 ipv4.addresses 192.168.1.100/24
nmcli connection modify eth0 ipv4.gateway 192.168.1.1
nmcli connection modify eth0 ipv4.dns "8.8.8.8 8.8.4.4"
nmcli connection modify eth0 ipv4.method manual

# Restart connection
nmcli connection down eth0
nmcli connection up eth0
```

---

## Firewalls and Security

### UFW (Uncomplicated Firewall)

Simple frontend for iptables:

```bash
# Install UFW
sudo apt install ufw

# Enable firewall
sudo ufw enable

# Check status
sudo ufw status
sudo ufw status verbose
sudo ufw status numbered

# Default policies
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow specific services
sudo ufw allow ssh              # Port 22
sudo ufw allow 80/tcp           # HTTP
sudo ufw allow 443/tcp          # HTTPS
sudo ufw allow 3000/tcp         # React dev server

# Allow from specific IP
sudo ufw allow from 192.168.1.50

# Allow from subnet
sudo ufw allow from 192.168.1.0/24

# Allow specific port from IP
sudo ufw allow from 192.168.1.50 to any port 22

# Deny specific port
sudo ufw deny 23                # Deny Telnet

# Delete rule
sudo ufw delete allow 80
sudo ufw delete 3               # By number

# Disable firewall
sudo ufw disable

# Reset firewall (remove all rules)
sudo ufw reset
```

### iptables (Advanced)

Direct kernel firewall configuration:

```bash
# View current rules
sudo iptables -L -v -n
sudo iptables -L INPUT -v -n

# Allow SSH
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Allow HTTP and HTTPS
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Allow established connections
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow loopback
sudo iptables -A INPUT -i lo -j ACCEPT

# Drop everything else
sudo iptables -A INPUT -j DROP

# Save rules (Ubuntu/Debian)
sudo apt install iptables-persistent
sudo netfilter-persistent save

# Flush all rules (careful!)
sudo iptables -F
```

### Practical Security Example: Securing a Web Server

```bash
# 1. Enable firewall
sudo ufw enable

# 2. Allow SSH (so you don't lock yourself out!)
sudo ufw allow 22/tcp

# 3. Allow HTTP/HTTPS
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# 4. Allow only from specific IP for management
sudo ufw allow from 203.0.113.10 to any port 3000

# 5. Rate limiting for SSH (prevent brute force)
sudo ufw limit ssh

# 6. Check configuration
sudo ufw status numbered

# 7. Monitor connections
sudo ss -tunap | grep :80
sudo ss -tunap | grep :443
```

---

## Network Troubleshooting

### Connectivity Testing

```bash
# Test Layer 3 (Network) - ICMP
ping 8.8.8.8                   # Test internet
ping 192.168.1.1               # Test gateway
ping -c 4 google.com           # Test DNS + internet

# Test Layer 4 (Transport) - TCP/UDP
nc -zv google.com 80           # Test TCP port
nc -zuv google.com 53          # Test UDP port

# Trace route to destination
traceroute google.com
mtr google.com                 # Better traceroute (continuous)

# Path MTU discovery
ping -M do -s 1472 google.com  # Test packet size
```

### Port Scanning

```bash
# Install nmap
sudo apt install nmap

# Scan single host
nmap 192.168.1.1

# Scan specific ports
nmap -p 80,443 192.168.1.1
nmap -p 1-1000 192.168.1.1

# Scan range
nmap 192.168.1.0/24

# Service detection
nmap -sV 192.168.1.1

# OS detection
sudo nmap -O 192.168.1.1

# Fast scan (top 100 ports)
nmap -F 192.168.1.1

# Scan your own system (security audit)
sudo nmap -sS -sV -O localhost
```

### Packet Capture and Analysis

```bash
# Capture all traffic on interface
sudo tcpdump -i eth0

# Capture HTTP traffic
sudo tcpdump -i eth0 port 80

# Capture to file
sudo tcpdump -i eth0 -w capture.pcap

# Read capture file
tcpdump -r capture.pcap

# Filter by host
sudo tcpdump -i eth0 host 192.168.1.100

# Filter by network
sudo tcpdump -i eth0 net 192.168.1.0/24

# Capture DNS queries
sudo tcpdump -i eth0 port 53

# Verbose output with ASCII
sudo tcpdump -i eth0 -A -vv

# Monitor React API calls
sudo tcpdump -i lo -n -A 'tcp port 3001'
```

### Common Issues and Solutions

**Issue**: Cannot reach internet
```bash
# 1. Check interface is up
ip link show

# 2. Check IP address
ip addr show

# 3. Check default gateway
ip route show

# 4. Test gateway
ping 192.168.1.1

# 5. Test DNS
ping 8.8.8.8
nslookup google.com

# 6. Check DNS configuration
cat /etc/resolv.conf
```

**Issue**: DNS not resolving
```bash
# 1. Test DNS directly
nslookup google.com 8.8.8.8

# 2. Flush DNS cache
sudo systemd-resolve --flush-caches

# 3. Change DNS server
sudo nano /etc/resolv.conf
# Add: nameserver 8.8.8.8

# 4. Restart networking
sudo systemctl restart systemd-networkd
```

**Issue**: Port already in use
```bash
# Find what's using the port
sudo ss -tlnp | grep :3000
sudo lsof -i :3000

# Kill the process
sudo kill -9 <PID>

# Or kill by port
sudo fuser -k 3000/tcp
```

---

## Practical Lab: Deploy React App with Nginx

Let's put it all together!

```bash
# 1. Install Nginx
sudo apt update
sudo apt install nginx

# 2. Check Nginx is running
sudo systemctl status nginx
sudo ss -tlnp | grep :80

# 3. Build React app
cd ~/my-react-app
npm run build

# 4. Copy build to web root
sudo cp -r build/* /var/www/html/

# 5. Configure Nginx
sudo nano /etc/nginx/sites-available/myapp
```

```nginx
server {
    listen 80;
    server_name myapp.local;
    root /var/www/html;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }

    # Proxy API requests to backend
    location /api {
        proxy_pass http://localhost:3001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
```

```bash
# 6. Enable site
sudo ln -s /etc/nginx/sites-available/myapp /etc/nginx/sites-enabled/
sudo nginx -t                    # Test configuration
sudo systemctl reload nginx

# 7. Add to /etc/hosts
echo "127.0.0.1 myapp.local" | sudo tee -a /etc/hosts

# 8. Configure firewall
sudo ufw allow 80/tcp

# 9. Test
curl http://myapp.local
# Or open in browser

# 10. Monitor logs
sudo tail -f /var/log/nginx/access.log
sudo tail -f /var/log/nginx/error.log
```

---

## Key Takeaways

1. **Networking is layered** - OSI/TCP-IP models organize communication
2. **IP addresses identify hosts** - Subnetting divides networks
3. **TCP provides reliability** - UDP provides speed
4. **DNS translates names** - Essential for web applications
5. **HTTP/HTTPS powers the web** - Understand requests/responses
6. **Firewalls protect systems** - Control incoming/outgoing traffic
7. **Troubleshooting is systematic** - Test layer by layer

---

## Next Steps

- Practice these commands daily
- Set up a home lab with VMs
- Monitor your own network traffic
- Learn Wireshark for deep packet analysis
- Move on to **Security Concepts**
- Understand WebSockets for React apps
- Learn about load balancing and CDNs

**For React/TypeScript Developers**: Understanding networking is crucial for debugging API calls, optimizing performance, securing applications, and deploying to production!
