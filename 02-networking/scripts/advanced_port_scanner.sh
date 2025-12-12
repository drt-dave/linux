#!/bin/bash

# Advanced Port Scanner
# Comprehensive port scanning with service detection
# For educational purposes only - use on authorized targets

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Banner
echo -e "${BLUE}"
echo "================================================"
echo "    Advanced Port Scanner v1.0"
echo "    For Authorized Testing Only"
echo "================================================"
echo -e "${NC}"

# Check if target is provided
if [ -z "$1" ]; then
    echo -e "${RED}[!] Usage: $0 <target_ip> [scan_type]${NC}"
    echo ""
    echo "Scan types:"
    echo "  quick  - Top 100 ports (default)"
    echo "  full   - All 65535 ports"
    echo "  custom - Specify port range"
    exit 1
fi

TARGET=$1
SCAN_TYPE=${2:-quick}

# Validate IP address
if ! [[ $TARGET =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    echo -e "${RED}[!] Invalid IP address${NC}"
    exit 1
fi

echo -e "${YELLOW}[*] Target: $TARGET${NC}"
echo -e "${YELLOW}[*] Scan Type: $SCAN_TYPE${NC}"
echo ""

# Check if host is up
echo -e "${YELLOW}[*] Checking if host is up...${NC}"
if ping -c 1 -W 1 $TARGET &>/dev/null; then
    echo -e "${GREEN}[+] Host is up${NC}"
else
    echo -e "${RED}[!] Host appears to be down or ICMP blocked${NC}"
    read -p "Continue anyway? (y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Common ports array
COMMON_PORTS=(21 22 23 25 53 80 110 111 135 139 143 443 445 993 995 1723 3306 3389 5900 8080)

# Port ranges based on scan type
case $SCAN_TYPE in
    quick)
        PORTS=("${COMMON_PORTS[@]}")
        ;;
    full)
        echo -e "${YELLOW}[*] Full scan will take considerable time...${NC}"
        PORTS=($(seq 1 65535))
        ;;
    custom)
        read -p "Enter port range (e.g., 1-1000): " PORT_RANGE
        START=$(echo $PORT_RANGE | cut -d'-' -f1)
        END=$(echo $PORT_RANGE | cut -d'-' -f2)
        PORTS=($(seq $START $END))
        ;;
    *)
        echo -e "${RED}[!] Invalid scan type${NC}"
        exit 1
        ;;
esac

echo -e "${YELLOW}[*] Scanning ${#PORTS[@]} ports...${NC}"
echo ""

# Service detection function
get_service() {
    case $1 in
        21) echo "FTP" ;;
        22) echo "SSH" ;;
        23) echo "Telnet" ;;
        25) echo "SMTP" ;;
        53) echo "DNS" ;;
        80) echo "HTTP" ;;
        110) echo "POP3" ;;
        111) echo "RPC" ;;
        135) echo "MSRPC" ;;
        139) echo "NetBIOS" ;;
        143) echo "IMAP" ;;
        443) echo "HTTPS" ;;
        445) echo "SMB" ;;
        993) echo "IMAPS" ;;
        995) echo "POP3S" ;;
        1433) echo "MSSQL" ;;
        1723) echo "PPTP" ;;
        3306) echo "MySQL" ;;
        3389) echo "RDP" ;;
        5432) echo "PostgreSQL" ;;
        5900) echo "VNC" ;;
        8080) echo "HTTP-ALT" ;;
        *) echo "Unknown" ;;
    esac
}

# Banner grabbing function
grab_banner() {
    timeout 2 bash -c "echo '' | nc -w 1 $TARGET $1 2>/dev/null | head -n 1 | tr -d '\r\n'"
}

# Scan ports
OPEN_PORTS=()
echo -e "${BLUE}PORT\tSTATE\tSERVICE\t\tBANNER${NC}"
echo "------------------------------------------------------------"

for PORT in "${PORTS[@]}"; do
    # Progress indicator for long scans
    if [ $((PORT % 1000)) -eq 0 ] && [ "$SCAN_TYPE" == "full" ]; then
        echo -e "${YELLOW}[*] Progress: $PORT/65535${NC}"
    fi

    # Check if port is open using /dev/tcp
    timeout 1 bash -c "echo >/dev/tcp/$TARGET/$PORT" 2>/dev/null

    if [ $? -eq 0 ]; then
        SERVICE=$(get_service $PORT)
        BANNER=$(grab_banner $PORT)

        if [ -z "$BANNER" ]; then
            BANNER="No banner"
        else
            BANNER=$(echo $BANNER | cut -c1-30)
        fi

        echo -e "${GREEN}$PORT\tOPEN\t$SERVICE\t\t$BANNER${NC}"
        OPEN_PORTS+=($PORT)
    fi
done

echo ""
echo -e "${GREEN}[+] Scan complete${NC}"
echo -e "${GREEN}[+] Open ports: ${#OPEN_PORTS[@]}${NC}"

# Summary
if [ ${#OPEN_PORTS[@]} -gt 0 ]; then
    echo ""
    echo -e "${YELLOW}[*] Summary of open ports:${NC}"
    for PORT in "${OPEN_PORTS[@]}"; do
        echo -e "    - Port $PORT: $(get_service $PORT)"
    done

    # Security recommendations
    echo ""
    echo -e "${YELLOW}[*] Security Notes:${NC}"
    for PORT in "${OPEN_PORTS[@]}"; do
        case $PORT in
            21)
                echo -e "    ${RED}[!] FTP (21): Check for anonymous login${NC}"
                ;;
            23)
                echo -e "    ${RED}[!] Telnet (23): Unencrypted, should be disabled${NC}"
                ;;
            445)
                echo -e "    ${RED}[!] SMB (445): Check for EternalBlue vulnerability${NC}"
                ;;
            3389)
                echo -e "    ${RED}[!] RDP (3389): Ensure strong passwords, check for BlueKeep${NC}"
                ;;
        esac
    done
else
    echo -e "${YELLOW}[*] No open ports found${NC}"
fi

echo ""
echo -e "${BLUE}[*] Scan completed at $(date)${NC}"
