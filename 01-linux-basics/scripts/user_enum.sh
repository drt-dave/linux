#!/bin/bash

##############################################
# User Enumeration & Privilege Escalation Script
# Purpose: Identify privilege escalation vectors
# Use: For authorized penetration testing only
##############################################

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}"
echo "╔═══════════════════════════════════════════╗"
echo "║  USER ENUMERATION & PRIVESC CHECKER       ║"
echo "╚═══════════════════════════════════════════╝"
echo -e "${NC}\n"

##############################################
# Current User Information
##############################################
echo -e "${YELLOW}[+] Current User Information${NC}"
echo "User: $(whoami)"
echo "ID: $(id)"
echo "Groups: $(groups)"
echo "Shell: $SHELL"
echo ""

##############################################
# Sudo Privileges
##############################################
echo -e "${YELLOW}[+] Checking Sudo Privileges${NC}"
sudo_check=$(sudo -l 2>&1)
if echo "$sudo_check" | grep -q "NOPASSWD"; then
    echo -e "${RED}[!] CRITICAL: NOPASSWD sudo entries found!${NC}"
    echo "$sudo_check"
elif echo "$sudo_check" | grep -q "may run"; then
    echo -e "${YELLOW}[!] Sudo privileges detected:${NC}"
    echo "$sudo_check"
else
    echo "[*] No sudo privileges or cannot check"
fi
echo ""

##############################################
# Privileged Groups
##############################################
echo -e "${YELLOW}[+] Checking for Privileged Group Memberships${NC}"
dangerous_groups=("sudo" "wheel" "docker" "lxd" "lxc" "disk" "video" "root" "adm")

for group in "${dangerous_groups[@]}"; do
    if groups | grep -q "$group"; then
        echo -e "${RED}[!] User is in '$group' group - Potential privilege escalation!${NC}"
    fi
done
echo ""

##############################################
# SUID Binaries
##############################################
echo -e "${YELLOW}[+] Finding SUID Binaries (Top 20)${NC}"
echo "[*] These binaries run with owner privileges..."
find / -perm -4000 -type f 2>/dev/null | head -20

# Check for exploitable SUID binaries
echo -e "\n${YELLOW}[+] Checking for Exploitable SUID Binaries${NC}"
exploitable=("nmap" "vim" "find" "bash" "more" "less" "nano" "cp" "mv" "awk" "perl" "python" "ruby" "lua" "php")

for binary in "${exploitable[@]}"; do
    suid_path=$(find / -name "$binary" -perm -4000 -type f 2>/dev/null | head -1)
    if [ -n "$suid_path" ]; then
        echo -e "${RED}[!] EXPLOITABLE SUID: $suid_path${NC}"
        echo "    Check GTFOBins: https://gtfobins.github.io/gtfobins/$binary/"
    fi
done
echo ""

##############################################
# File Capabilities
##############################################
echo -e "${YELLOW}[+] Checking for Dangerous Capabilities${NC}"
if command -v getcap &> /dev/null; then
    caps=$(getcap -r / 2>/dev/null)
    if [ -n "$caps" ]; then
        echo "$caps"
        if echo "$caps" | grep -q "cap_setuid"; then
            echo -e "${RED}[!] cap_setuid found - Privilege escalation possible!${NC}"
        fi
    else
        echo "[*] No special capabilities found"
    fi
else
    echo "[*] getcap not available"
fi
echo ""

##############################################
# Writable /etc Files
##############################################
echo -e "${YELLOW}[+] Checking for Writable /etc Files${NC}"
writable_etc=$(find /etc -writable 2>/dev/null)
if [ -n "$writable_etc" ]; then
    echo -e "${RED}[!] Writable /etc files found:${NC}"
    echo "$writable_etc"
else
    echo "[*] No writable /etc files"
fi
echo ""

##############################################
# Password File Permissions
##############################################
echo -e "${YELLOW}[+] Checking Critical File Permissions${NC}"

# Check /etc/passwd
if [ -w /etc/passwd ]; then
    echo -e "${RED}[!] CRITICAL: /etc/passwd is writable!${NC}"
    echo "    You can add a new root user!"
else
    echo "[*] /etc/passwd: Read-only (normal)"
fi

# Check /etc/shadow
if [ -r /etc/shadow ]; then
    echo -e "${RED}[!] CRITICAL: /etc/shadow is readable!${NC}"
    echo "    You can crack password hashes!"
else
    echo "[*] /etc/shadow: Not readable (normal)"
fi

# Check /root
if [ -r /root ]; then
    echo -e "${RED}[!] /root directory is readable!${NC}"
else
    echo "[*] /root: Not accessible (normal)"
fi
echo ""

##############################################
# SSH Keys
##############################################
echo -e "${YELLOW}[+] Searching for SSH Private Keys${NC}"
ssh_keys=$(find / -name "id_rsa" -o -name "id_dsa" -o -name "id_ecdsa" -o -name "id_ed25519" 2>/dev/null)
if [ -n "$ssh_keys" ]; then
    echo "[*] SSH keys found:"
    echo "$ssh_keys"

    # Check for keys without passwords
    for key in $ssh_keys; do
        if [ -r "$key" ]; then
            if grep -q "ENCRYPTED" "$key"; then
                echo "    $key (encrypted)"
            else
                echo -e "${YELLOW}    $key ${RED}(NOT encrypted!)${NC}"
            fi
        fi
    done
else
    echo "[*] No SSH keys found"
fi
echo ""

##############################################
# Cron Jobs
##############################################
echo -e "${YELLOW}[+] Checking Cron Jobs${NC}"

# System crontab
if [ -r /etc/crontab ]; then
    echo "[*] /etc/crontab:"
    cat /etc/crontab | grep -v "^#" | grep -v "^$"
fi

# Writable cron jobs
echo "[*] Checking for writable cron scripts..."
for crondir in /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly; do
    if [ -d "$crondir" ]; then
        writable=$(find "$crondir" -writable 2>/dev/null)
        if [ -n "$writable" ]; then
            echo -e "${RED}[!] Writable cron scripts in $crondir:${NC}"
            echo "$writable"
        fi
    fi
done
echo ""

##############################################
# Interesting Processes
##############################################
echo -e "${YELLOW}[+] Checking for Interesting Running Processes${NC}"
echo "[*] Processes running as root:"
ps aux | grep root | grep -v grep | head -10
echo ""

##############################################
# World-Writable Directories
##############################################
echo -e "${YELLOW}[+] Finding World-Writable Directories${NC}"
echo "[*] These can be used to upload/execute payloads..."
find / -type d -perm -0002 2>/dev/null | grep -v "proc\|sys" | head -10
echo ""

##############################################
# NFS Exports
##############################################
echo -e "${YELLOW}[+] Checking NFS Exports${NC}"
if [ -r /etc/exports ]; then
    exports=$(cat /etc/exports | grep -v "^#" | grep -v "^$")
    if [ -n "$exports" ]; then
        echo "$exports"
        if echo "$exports" | grep -q "no_root_squash"; then
            echo -e "${RED}[!] no_root_squash found - Privilege escalation possible!${NC}"
        fi
    else
        echo "[*] No NFS exports"
    fi
else
    echo "[*] No /etc/exports file"
fi
echo ""

##############################################
# Environment Variables
##############################################
echo -e "${YELLOW}[+] Checking Environment Variables for Secrets${NC}"
env_secrets=$(env | grep -i "pass\|pwd\|secret\|key\|token" 2>/dev/null)
if [ -n "$env_secrets" ]; then
    echo -e "${YELLOW}[!] Potential secrets in environment:${NC}"
    echo "$env_secrets"
else
    echo "[*] No obvious secrets in environment"
fi
echo ""

##############################################
# Summary
##############################################
echo -e "${GREEN}"
echo "╔═══════════════════════════════════════════╗"
echo "║           ENUMERATION COMPLETE            ║"
echo "╚═══════════════════════════════════════════╝"
echo -e "${NC}"

echo -e "${YELLOW}Recommended Next Steps:${NC}"
echo "1. Check GTFOBins for SUID binary exploits"
echo "2. Try sudo -l and test each command"
echo "3. Search for credentials in config files"
echo "4. Analyze writable cron jobs"
echo "5. Check for kernel exploits: uname -a"
echo ""
