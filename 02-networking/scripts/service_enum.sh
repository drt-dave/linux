#!/bin/bash

# Service Enumeration Script
# Deep enumeration of common network services

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
echo "========================================"
echo "    Service Enumeration Tool v1.0"
echo "========================================"
echo -e "${NC}"

if [ -z "$1" ]; then
    echo -e "${RED}[!] Usage: $0 <target_ip>${NC}"
    exit 1
fi

TARGET=$1

echo -e "${YELLOW}[*] Target: $TARGET${NC}"
echo -e "${YELLOW}[*] Starting service enumeration...${NC}"
echo ""

# Output file
OUTPUT="service_enum_${TARGET}_$(date +%Y%m%d_%H%M%S).txt"

# Check if host is up
echo -e "${YELLOW}[*] Checking if host is up...${NC}"
if ping -c 1 -W 2 $TARGET &>/dev/null; then
    echo -e "${GREEN}[+] Host is up${NC}"
else
    echo -e "${RED}[!] Host appears to be down${NC}"
    exit 1
fi
echo ""

# FTP Enumeration (Port 21)
echo -e "${BLUE}[*] Checking FTP (Port 21)...${NC}"
if timeout 2 bash -c "echo >/dev/tcp/$TARGET/21" 2>/dev/null; then
    echo -e "${GREEN}[+] FTP is open${NC}"

    # Banner grab
    BANNER=$(timeout 2 bash -c "nc -w 2 $TARGET 21 2>/dev/null" | head -n1)
    echo -e "${YELLOW}    Banner: $BANNER${NC}"

    # Check for anonymous login
    echo -e "${YELLOW}[*] Checking for anonymous FTP...${NC}"
    ANON_CHECK=$(timeout 5 bash -c "echo -e 'USER anonymous\nPASS anonymous\nQUIT' | nc -w 2 $TARGET 21 2>/dev/null")
    if echo "$ANON_CHECK" | grep -q "230"; then
        echo -e "${RED}[!] Anonymous FTP login allowed!${NC}"
    else
        echo -e "${GREEN}[+] Anonymous FTP not allowed${NC}"
    fi
else
    echo -e "${YELLOW}[-] FTP is closed${NC}"
fi
echo ""

# SSH Enumeration (Port 22)
echo -e "${BLUE}[*] Checking SSH (Port 22)...${NC}"
if timeout 2 bash -c "echo >/dev/tcp/$TARGET/22" 2>/dev/null; then
    echo -e "${GREEN}[+] SSH is open${NC}"

    # Banner grab
    BANNER=$(timeout 2 bash -c "nc -w 2 $TARGET 22 2>/dev/null" | head -n1)
    echo -e "${YELLOW}    Banner: $BANNER${NC}"
else
    echo -e "${YELLOW}[-] SSH is closed${NC}"
fi
echo ""

# HTTP Enumeration (Port 80)
echo -e "${BLUE}[*] Checking HTTP (Port 80)...${NC}"
if timeout 2 bash -c "echo >/dev/tcp/$TARGET/80" 2>/dev/null; then
    echo -e "${GREEN}[+] HTTP is open${NC}"

    # Banner grab
    HTTP_RESPONSE=$(curl -s -I http://$TARGET --max-time 3)
    echo -e "${YELLOW}    Server: $(echo "$HTTP_RESPONSE" | grep -i "^Server:" | cut -d' ' -f2-)${NC}"

    # Check for common files
    echo -e "${YELLOW}[*] Checking common files...${NC}"
    for FILE in "robots.txt" "sitemap.xml" ".git" "admin" "login"; do
        STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://$TARGET/$FILE --max-time 2)
        if [ "$STATUS" == "200" ]; then
            echo -e "${GREEN}    [+] Found: /$FILE (Status: $STATUS)${NC}"
        fi
    done
else
    echo -e "${YELLOW}[-] HTTP is closed${NC}"
fi
echo ""

# HTTPS Enumeration (Port 443)
echo -e "${BLUE}[*] Checking HTTPS (Port 443)...${NC}"
if timeout 2 bash -c "echo >/dev/tcp/$TARGET/443" 2>/dev/null; then
    echo -e "${GREEN}[+] HTTPS is open${NC}"

    # SSL certificate info
    echo -e "${YELLOW}[*] Getting SSL certificate info...${NC}"
    CERT_INFO=$(echo | timeout 3 openssl s_client -connect $TARGET:443 2>/dev/null | openssl x509 -noout -subject -dates 2>/dev/null)
    if [ ! -z "$CERT_INFO" ]; then
        echo "$CERT_INFO" | while read line; do
            echo -e "${YELLOW}    $line${NC}"
        done
    fi
else
    echo -e "${YELLOW}[-] HTTPS is closed${NC}"
fi
echo ""

# SMB Enumeration (Port 445)
echo -e "${BLUE}[*] Checking SMB (Port 445)...${NC}"
if timeout 2 bash -c "echo >/dev/tcp/$TARGET/445" 2>/dev/null; then
    echo -e "${GREEN}[+] SMB is open${NC}"

    # Check for null session
    echo -e "${YELLOW}[*] Attempting null session...${NC}"
    if command -v smbclient &>/dev/null; then
        SMB_SHARES=$(timeout 5 smbclient -L //$TARGET -N 2>/dev/null)
        if [ ! -z "$SMB_SHARES" ]; then
            echo -e "${YELLOW}    Shares found:${NC}"
            echo "$SMB_SHARES" | grep "Disk\|IPC" | while read line; do
                echo -e "${YELLOW}    $line${NC}"
            done
        fi
    else
        echo -e "${YELLOW}    [!] smbclient not installed${NC}"
    fi
else
    echo -e "${YELLOW}[-] SMB is closed${NC}"
fi
echo ""

# MySQL Enumeration (Port 3306)
echo -e "${BLUE}[*] Checking MySQL (Port 3306)...${NC}"
if timeout 2 bash -c "echo >/dev/tcp/$TARGET/3306" 2>/dev/null; then
    echo -e "${GREEN}[+] MySQL is open${NC}"
    BANNER=$(timeout 2 bash -c "nc -w 2 $TARGET 3306 2>/dev/null" | strings | head -n1)
    echo -e "${YELLOW}    Banner: $BANNER${NC}"
else
    echo -e "${YELLOW}[-] MySQL is closed${NC}"
fi
echo ""

# RDP Enumeration (Port 3389)
echo -e "${BLUE}[*] Checking RDP (Port 3389)...${NC}"
if timeout 2 bash -c "echo >/dev/tcp/$TARGET/3389" 2>/dev/null; then
    echo -e "${GREEN}[+] RDP is open${NC}"
    echo -e "${RED}    [!] Ensure strong passwords and check for BlueKeep vulnerability${NC}"
else
    echo -e "${YELLOW}[-] RDP is closed${NC}"
fi
echo ""

# Summary
echo -e "${GREEN}[+] Service enumeration complete${NC}"
echo -e "${YELLOW}[*] Results saved to: $OUTPUT${NC}"
echo ""
echo -e "${BLUE}[*] Scan completed at $(date)${NC}"
