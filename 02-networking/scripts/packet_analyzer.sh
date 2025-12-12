#!/bin/bash

# Packet Analyzer - Network traffic monitoring wrapper
# Educational purposes only

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
echo "========================================"
echo "    Packet Analyzer v1.0"
echo "========================================"
echo -e "${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[!] This script must be run as root${NC}"
    exit 1
fi

# Get interface
if [ -z "$1" ]; then
    echo -e "${YELLOW}[*] Available interfaces:${NC}"
    ip link show | grep -E "^[0-9]+:" | awk -F': ' '{print "    " $2}'
    echo ""
    read -p "Enter interface (or press Enter for default): " INTERFACE

    if [ -z "$INTERFACE" ]; then
        INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
    fi
else
    INTERFACE=$1
fi

echo -e "${YELLOW}[*] Using interface: $INTERFACE${NC}"
echo ""

# Main menu
echo "Select analysis mode:"
echo "1) Live packet capture"
echo "2) Analyze existing capture file"
echo "3) Monitor specific protocol (HTTP/DNS/FTP)"
echo "4) Connection tracker"
echo "5) Protocol statistics"
read -p "Choice [1-5]: " CHOICE

case $CHOICE in
    1)
        # Live packet capture
        OUTPUT="capture_$(date +%Y%m%d_%H%M%S).pcap"
        echo -e "${YELLOW}[*] Starting live capture on $INTERFACE${NC}"
        echo -e "${YELLOW}[*] Press Ctrl+C to stop${NC}"
        echo -e "${YELLOW}[*] Saving to: $OUTPUT${NC}"
        echo ""

        tcpdump -i $INTERFACE -w $OUTPUT

        echo ""
        echo -e "${GREEN}[+] Capture saved to: $OUTPUT${NC}"
        echo -e "${YELLOW}[*] Analyze with: wireshark $OUTPUT${NC}"
        ;;

    2)
        # Analyze existing file
        read -p "Enter capture file path: " CAPFILE

        if [ ! -f "$CAPFILE" ]; then
            echo -e "${RED}[!] File not found${NC}"
            exit 1
        fi

        echo -e "${YELLOW}[*] Analyzing $CAPFILE${NC}"
        echo ""

        echo -e "${BLUE}[*] Packet count:${NC}"
        tcpdump -r $CAPFILE | wc -l

        echo ""
        echo -e "${BLUE}[*] Protocol distribution:${NC}"
        tcpdump -qns 0 -r $CAPFILE | awk '{print $2}' | sort | uniq -c | sort -rn | head -10

        echo ""
        echo -e "${BLUE}[*] Top talkers (IP addresses):${NC}"
        tcpdump -n -r $CAPFILE | awk '{print $3}' | cut -d'.' -f1-4 | sort | uniq -c | sort -rn | head -10
        ;;

    3)
        # Monitor specific protocol
        echo "Select protocol:"
        echo "1) HTTP (port 80)"
        echo "2) HTTPS (port 443)"
        echo "3) DNS (port 53)"
        echo "4) FTP (port 21)"
        echo "5) SSH (port 22)"
        read -p "Choice: " PROTO_CHOICE

        case $PROTO_CHOICE in
            1) FILTER="tcp port 80"; PROTO="HTTP" ;;
            2) FILTER="tcp port 443"; PROTO="HTTPS" ;;
            3) FILTER="udp port 53"; PROTO="DNS" ;;
            4) FILTER="tcp port 21"; PROTO="FTP" ;;
            5) FILTER="tcp port 22"; PROTO="SSH" ;;
            *) echo "Invalid choice"; exit 1 ;;
        esac

        echo -e "${YELLOW}[*] Monitoring $PROTO traffic on $INTERFACE${NC}"
        echo -e "${YELLOW}[*] Press Ctrl+C to stop${NC}"
        echo ""

        tcpdump -i $INTERFACE -A "$FILTER"
        ;;

    4)
        # Connection tracker
        echo -e "${YELLOW}[*] Tracking connections on $INTERFACE${NC}"
        echo -e "${YELLOW}[*] Press Ctrl+C to stop${NC}"
        echo ""

        tcpdump -i $INTERFACE -n | awk '
            {
                src = $3
                dst = $5
                if (src && dst) {
                    conn = src " -> " dst
                    if (!(conn in connections)) {
                        connections[conn] = 1
                        print "[NEW] " conn
                    }
                }
            }
        '
        ;;

    5)
        # Protocol statistics
        DURATION=10
        echo -e "${YELLOW}[*] Collecting protocol statistics for $DURATION seconds...${NC}"

        TMPFILE="/tmp/packet_stats_$$.pcap"
        timeout $DURATION tcpdump -i $INTERFACE -w $TMPFILE 2>/dev/null

        echo ""
        echo -e "${BLUE}[*] Protocol Statistics:${NC}"
        echo ""

        TOTAL=$(tcpdump -r $TMPFILE 2>/dev/null | wc -l)
        TCP=$(tcpdump -r $TMPFILE tcp 2>/dev/null | wc -l)
        UDP=$(tcpdump -r $TMPFILE udp 2>/dev/null | wc -l)
        ICMP=$(tcpdump -r $TMPFILE icmp 2>/dev/null | wc -l)

        echo -e "${GREEN}Total packets: $TOTAL${NC}"
        echo -e "${GREEN}TCP: $TCP ($(( (TCP * 100) / TOTAL ))%)${NC}"
        echo -e "${GREEN}UDP: $UDP ($(( (UDP * 100) / TOTAL ))%)${NC}"
        echo -e "${GREEN}ICMP: $ICMP ($(( (ICMP * 100) / TOTAL ))%)${NC}"

        echo ""
        echo -e "${BLUE}[*] Top 5 destination ports:${NC}"
        tcpdump -n -r $TMPFILE 2>/dev/null | awk '{print $5}' | cut -d'.' -f5 | cut -d':' -f1 | sort | uniq -c | sort -rn | head -5

        rm -f $TMPFILE
        ;;

    *)
        echo -e "${RED}[!] Invalid choice${NC}"
        exit 1
        ;;
esac

echo ""
echo -e "${BLUE}[*] Analysis completed at $(date)${NC}"
