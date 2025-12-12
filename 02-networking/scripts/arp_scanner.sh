#!/bin/bash

# ARP Scanner - Discover hosts on local network
# Educational purposes only

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
echo "========================================"
echo "    ARP Network Scanner v1.0"
echo "========================================"
echo -e "${NC}"

# Get default interface and network
INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
MY_IP=$(ip addr show $INTERFACE | grep "inet " | awk '{print $2}' | cut -d'/' -f1)
NETWORK=$(ip addr show $INTERFACE | grep "inet " | awk '{print $2}' | cut -d'/' -f1 | cut -d'.' -f1-3)

if [ -z "$INTERFACE" ] || [ -z "$MY_IP" ]; then
    echo -e "${RED}[!] Could not determine network interface${NC}"
    exit 1
fi

echo -e "${YELLOW}[*] Interface: $INTERFACE${NC}"
echo -e "${YELLOW}[*] Your IP: $MY_IP${NC}"
echo -e "${YELLOW}[*] Network: $NETWORK.0/24${NC}"
echo -e "${YELLOW}[*] Scanning network...${NC}"
echo ""

# Create output file
OUTPUT="arp_scan_$(date +%Y%m%d_%H%M%S).txt"

echo -e "${BLUE}IP ADDRESS\t\tMAC ADDRESS\t\tHOSTNAME${NC}"
echo "----------------------------------------------------------------"

LIVE_HOSTS=0

# Scan network range
for i in $(seq 1 254); do
    IP="$NETWORK.$i"

    # Skip our own IP
    if [ "$IP" == "$MY_IP" ]; then
        continue
    fi

    # Ping once with short timeout
    ping -c 1 -W 1 $IP >/dev/null 2>&1 &
done

# Wait for pings to complete
sleep 3

# Check ARP table for discovered hosts
arp -n | grep -v "incomplete" | grep -v "Address" | while read line; do
    IP=$(echo $line | awk '{print $1}')
    MAC=$(echo $line | awk '{print $3}')

    # Skip invalid entries
    if [ "$MAC" == "(incomplete)" ] || [ -z "$MAC" ]; then
        continue
    fi

    # Try to get hostname
    HOSTNAME=$(host $IP 2>/dev/null | awk '{print $NF}' | sed 's/\.$//')
    if [ -z "$HOSTNAME" ] || [[ $HOSTNAME =~ "not found" ]]; then
        HOSTNAME="Unknown"
    fi

    # Identify vendor from MAC (first 3 octets)
    MAC_PREFIX=$(echo $MAC | cut -d':' -f1-3 | tr '[:lower:]' '[:upper:]')
    case $MAC_PREFIX in
        "08:00:27") VENDOR="VirtualBox" ;;
        "00:0C:29"|"00:50:56") VENDOR="VMware" ;;
        "00:15:5D") VENDOR="Hyper-V" ;;
        "B8:27:EB"|"DC:A6:32") VENDOR="Raspberry Pi" ;;
        *) VENDOR="Unknown" ;;
    esac

    echo -e "${GREEN}$IP\t\t$MAC\t$HOSTNAME${NC}"
    echo "$IP - $MAC - $HOSTNAME - $VENDOR" >> $OUTPUT
    LIVE_HOSTS=$((LIVE_HOSTS + 1))
done

echo ""
echo -e "${GREEN}[+] Scan complete${NC}"
echo -e "${GREEN}[+] Live hosts found: $LIVE_HOSTS${NC}"
echo -e "${YELLOW}[*] Results saved to: $OUTPUT${NC}"

# Show ARP cache
echo ""
echo -e "${YELLOW}[*] Full ARP table:${NC}"
arp -n

echo ""
echo -e "${BLUE}[*] Scan completed at $(date)${NC}"
