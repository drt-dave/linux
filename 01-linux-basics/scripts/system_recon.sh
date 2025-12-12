#!/bin/bash

##############################################
# System Reconnaissance Script
# Purpose: Perform initial enumeration on a Linux system
# Use: For authorized penetration testing only
##############################################

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Banner
echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════╗"
echo "║     LINUX SYSTEM RECONNAISSANCE SCRIPT       ║"
echo "║          For Authorized Testing Only         ║"
echo "╚══════════════════════════════════════════════╝"
echo -e "${NC}"

# Create output directory
OUTPUT_DIR="recon_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"
echo -e "${GREEN}[+] Output directory: $OUTPUT_DIR${NC}\n"

##############################################
# FUNCTION: System Information
##############################################
echo -e "${YELLOW}[*] Gathering System Information...${NC}"
{
    echo "=== SYSTEM INFORMATION ==="
    echo "Hostname: $(hostname)"
    echo "Kernel: $(uname -r)"
    echo "OS: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2)"
    echo "Architecture: $(uname -m)"
    echo "Date: $(date)"
    echo ""
} > "$OUTPUT_DIR/system_info.txt"
echo -e "${GREEN}[✓] System info saved${NC}"

##############################################
# FUNCTION: User Enumeration
##############################################
echo -e "${YELLOW}[*] Enumerating Users...${NC}"
{
    echo "=== ALL USERS ==="
    cat /etc/passwd | cut -d: -f1
    echo ""

    echo "=== USERS WITH BASH SHELL ==="
    cat /etc/passwd | grep bash | cut -d: -f1
    echo ""

    echo "=== USERS WITH UID 0 (ROOT PRIVILEGES) ==="
    awk -F: '$3 == 0 {print $1}' /etc/passwd
    echo ""

    echo "=== CURRENT USER INFO ==="
    whoami
    id
    echo ""

    echo "=== CURRENT USER GROUPS ==="
    groups
    echo ""

    echo "=== SUDO PRIVILEGES ==="
    sudo -l 2>/dev/null || echo "Cannot check sudo privileges"
    echo ""
} > "$OUTPUT_DIR/users.txt"
echo -e "${GREEN}[✓] User enumeration complete${NC}"

##############################################
# FUNCTION: Find SUID/SGID Binaries
##############################################
echo -e "${YELLOW}[*] Searching for SUID/SGID binaries...${NC}"
{
    echo "=== SUID BINARIES (Potential Privilege Escalation) ==="
    find / -perm -4000 -type f 2>/dev/null
    echo ""

    echo "=== SGID BINARIES ==="
    find / -perm -2000 -type f 2>/dev/null
    echo ""
} > "$OUTPUT_DIR/suid_sgid.txt"
echo -e "${GREEN}[✓] SUID/SGID search complete${NC}"

##############################################
# FUNCTION: Find Writable Directories
##############################################
echo -e "${YELLOW}[*] Finding writable directories...${NC}"
{
    echo "=== WORLD-WRITABLE DIRECTORIES ==="
    find / -type d -perm -0002 2>/dev/null | head -20
    echo ""

    echo "=== WRITABLE /etc DIRECTORIES ==="
    find /etc -writable -type d 2>/dev/null
    echo ""
} > "$OUTPUT_DIR/writable_dirs.txt"
echo -e "${GREEN}[✓] Writable directories found${NC}"

##############################################
# FUNCTION: Credential Hunting
##############################################
echo -e "${YELLOW}[*] Hunting for credentials...${NC}"
{
    echo "=== FILES CONTAINING 'PASSWORD' IN NAME ==="
    find / -name "*password*" 2>/dev/null | head -20
    echo ""

    echo "=== SSH PRIVATE KEYS ==="
    find / -name "id_rsa" -o -name "id_dsa" 2>/dev/null
    echo ""

    echo "=== AUTHORIZED_KEYS FILES ==="
    find / -name "authorized_keys" 2>/dev/null
    echo ""

    echo "=== BACKUP FILES ==="
    find / -name "*.bak" -o -name "*.backup" 2>/dev/null | head -20
    echo ""

    echo "=== DATABASE FILES ==="
    find / -name "*.db" -o -name "*.sqlite" -o -name "*.sqlite3" 2>/dev/null | head -20
    echo ""
} > "$OUTPUT_DIR/credentials.txt"
echo -e "${GREEN}[✓] Credential hunting complete${NC}"

##############################################
# FUNCTION: Network Information
##############################################
echo -e "${YELLOW}[*] Gathering network information...${NC}"
{
    echo "=== NETWORK INTERFACES ==="
    ip addr 2>/dev/null || ifconfig 2>/dev/null
    echo ""

    echo "=== ROUTING TABLE ==="
    ip route 2>/dev/null || route -n 2>/dev/null
    echo ""

    echo "=== LISTENING PORTS ==="
    ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null
    echo ""

    echo "=== ACTIVE CONNECTIONS ==="
    ss -tupn 2>/dev/null || netstat -tupn 2>/dev/null
    echo ""

    echo "=== DNS SERVERS ==="
    cat /etc/resolv.conf 2>/dev/null
    echo ""
} > "$OUTPUT_DIR/network.txt"
echo -e "${GREEN}[✓] Network info gathered${NC}"

##############################################
# FUNCTION: Running Processes
##############################################
echo -e "${YELLOW}[*] Checking running processes...${NC}"
{
    echo "=== RUNNING PROCESSES ==="
    ps aux
    echo ""

    echo "=== PROCESSES RUNNING AS ROOT ==="
    ps aux | grep root
    echo ""
} > "$OUTPUT_DIR/processes.txt"
echo -e "${GREEN}[✓] Process list saved${NC}"

##############################################
# FUNCTION: Scheduled Tasks (Cron Jobs)
##############################################
echo -e "${YELLOW}[*] Checking scheduled tasks...${NC}"
{
    echo "=== SYSTEM CRONTAB ==="
    cat /etc/crontab 2>/dev/null
    echo ""

    echo "=== CRON DIRECTORIES ==="
    ls -la /etc/cron.* 2>/dev/null
    echo ""

    echo "=== USER CRONTABS ==="
    for user in $(cat /etc/passwd | cut -d: -f1); do
        echo "--- $user ---"
        crontab -l -u $user 2>/dev/null
    done
    echo ""
} > "$OUTPUT_DIR/cron_jobs.txt"
echo -e "${GREEN}[✓] Cron jobs enumerated${NC}"

##############################################
# FUNCTION: Installed Software
##############################################
echo -e "${YELLOW}[*] Checking installed software...${NC}"
{
    echo "=== INSTALLED PACKAGES (first 50) ==="
    if command -v dpkg &> /dev/null; then
        dpkg -l | head -50
    elif command -v rpm &> /dev/null; then
        rpm -qa | head -50
    else
        echo "Package manager not found"
    fi
    echo ""

    echo "=== USEFUL TOOLS INSTALLED ==="
    for tool in gcc g++ python python3 perl php ruby nc netcat nmap curl wget git; do
        if command -v $tool &> /dev/null; then
            echo "$tool: $(which $tool)"
        fi
    done
    echo ""
} > "$OUTPUT_DIR/software.txt"
echo -e "${GREEN}[✓] Software enumeration complete${NC}"

##############################################
# FUNCTION: Interesting Files
##############################################
echo -e "${YELLOW}[*] Searching for interesting files...${NC}"
{
    echo "=== READABLE /etc/shadow ==="
    if [ -r /etc/shadow ]; then
        echo "WARNING: /etc/shadow is readable!"
    else
        echo "/etc/shadow is not readable (normal)"
    fi
    echo ""

    echo "=== WEB DIRECTORIES ==="
    ls -la /var/www/ 2>/dev/null
    ls -la /var/www/html/ 2>/dev/null
    echo ""

    echo "=== LOG FILES ==="
    ls -la /var/log/ 2>/dev/null | head -20
    echo ""

    echo "=== HIDDEN FILES IN /tmp ==="
    ls -la /tmp 2>/dev/null | grep "^\."
    echo ""
} > "$OUTPUT_DIR/interesting_files.txt"
echo -e "${GREEN}[✓] Interesting files cataloged${NC}"

##############################################
# FUNCTION: Capabilities
##############################################
echo -e "${YELLOW}[*] Checking for file capabilities...${NC}"
{
    echo "=== FILE CAPABILITIES ==="
    if command -v getcap &> /dev/null; then
        getcap -r / 2>/dev/null
    else
        echo "getcap not available"
    fi
    echo ""
} > "$OUTPUT_DIR/capabilities.txt"
echo -e "${GREEN}[✓] Capabilities check complete${NC}"

##############################################
# Summary Report
##############################################
echo -e "\n${BLUE}=== RECONNAISSANCE SUMMARY ===${NC}"
{
    echo "=== RECONNAISSANCE SUMMARY ==="
    echo "Scan Date: $(date)"
    echo "Hostname: $(hostname)"
    echo ""
    echo "Files Generated:"
    ls -lh "$OUTPUT_DIR"
    echo ""
    echo "Key Findings:"
    echo "- Users with bash: $(cat /etc/passwd | grep bash | wc -l)"
    echo "- SUID binaries: $(find / -perm -4000 -type f 2>/dev/null | wc -l)"
    echo "- Running processes: $(ps aux | wc -l)"
    echo ""
    echo "Check individual files in $OUTPUT_DIR for detailed information"
} | tee "$OUTPUT_DIR/SUMMARY.txt"

echo -e "\n${GREEN}[✓] Reconnaissance complete!${NC}"
echo -e "${YELLOW}[*] Results saved in: $OUTPUT_DIR${NC}\n"

# Set appropriate permissions on output directory
chmod 700 "$OUTPUT_DIR"

echo -e "${BLUE}Remember: Use this tool only on systems you're authorized to test!${NC}"
