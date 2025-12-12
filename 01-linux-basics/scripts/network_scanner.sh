#!/bin/bash

##############################################
# Basic Network Scanner (without nmap)
# Purpose: Discover hosts and open ports on local network
# Use: For authorized network testing only
##############################################

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
echo "╔══════════════════════════════════════════╗"
echo "║      BASIC NETWORK SCANNER               ║"
echo "║      (Pure Bash Implementation)          ║"
echo "╚══════════════════════════════════════════╝"
echo -e "${NC}\n"

##############################################
# Get Network Information
##############################################
get_local_network() {
    echo -e "${YELLOW}[+] Detecting Local Network...${NC}"

    # Get IP address
    if command -v ip &> /dev/null; then
        local_ip=$(ip addr | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v "127.0.0.1" | head -1)
    else
        local_ip=$(ifconfig | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v "127.0.0.1" | head -1)
    fi

    if [ -z "$local_ip" ]; then
        echo -e "${RED}[!] Could not detect local IP${NC}"
        exit 1
    fi

    # Calculate network prefix
    IFS='.' read -r -a ip_parts <<< "$local_ip"
    network_prefix="${ip_parts[0]}.${ip_parts[1]}.${ip_parts[2]}"

    echo "[*] Local IP: $local_ip"
    echo "[*] Network: $network_prefix.0/24"
    echo ""
}

##############################################
# Ping Sweep
##############################################
ping_sweep() {
    local network=$1
    echo -e "${YELLOW}[+] Performing Ping Sweep on $network.0/24${NC}"
    echo "[*] This may take a while..."

    active_hosts=()

    for i in {1..254}; do
        ip="$network.$i"

        # Show progress
        if [ $((i % 50)) -eq 0 ]; then
            echo -n "."
        fi

        # Ping with 1 second timeout
        if ping -c 1 -W 1 "$ip" &>/dev/null; then
            active_hosts+=("$ip")
        fi
    done

    echo ""
    echo -e "${GREEN}[✓] Ping sweep complete${NC}"
    echo "[*] Active hosts: ${#active_hosts[@]}"
    echo ""

    if [ ${#active_hosts[@]} -gt 0 ]; then
        echo -e "${GREEN}Active Hosts:${NC}"
        for host in "${active_hosts[@]}"; do
            # Try to get hostname
            hostname=$(getent hosts "$host" 2>/dev/null | awk '{print $2}')
            if [ -n "$hostname" ]; then
                echo "  $host ($hostname)"
            else
                echo "  $host"
            fi
        done
        echo ""
    fi
}

##############################################
# Port Scanner (TCP Connect)
##############################################
port_scan() {
    local target=$1
    local ports=("21" "22" "23" "25" "53" "80" "110" "143" "443" "445" "3306" "3389" "5432" "8080" "8443")

    echo -e "${YELLOW}[+] Scanning common ports on $target${NC}"

    open_ports=()

    for port in "${ports[@]}"; do
        # Attempt TCP connection with timeout
        (echo >/dev/tcp/"$target"/"$port") &>/dev/null && {
            open_ports+=("$port")
        }
    done

    if [ ${#open_ports[@]} -gt 0 ]; then
        echo -e "${GREEN}[*] Open ports on $target:${NC}"
        for port in "${open_ports[@]}"; do
            service=$(get_service_name "$port")
            echo "  Port $port/tcp - $service"
        done
        echo ""
    else
        echo "[*] No common ports open on $target"
        echo ""
    fi
}

##############################################
# Service Name Helper
##############################################
get_service_name() {
    case $1 in
        21) echo "FTP" ;;
        22) echo "SSH" ;;
        23) echo "Telnet" ;;
        25) echo "SMTP" ;;
        53) echo "DNS" ;;
        80) echo "HTTP" ;;
        110) echo "POP3" ;;
        143) echo "IMAP" ;;
        443) echo "HTTPS" ;;
        445) echo "SMB" ;;
        3306) echo "MySQL" ;;
        3389) echo "RDP" ;;
        5432) echo "PostgreSQL" ;;
        8080) echo "HTTP-Proxy" ;;
        8443) echo "HTTPS-Alt" ;;
        *) echo "Unknown" ;;
    esac
}

##############################################
# Quick Port Scanner for single host
##############################################
quick_port_scan() {
    local target=$1
    echo -e "${YELLOW}[+] Quick scan: Top 20 ports on $target${NC}"

    common_ports=(20 21 22 23 25 53 80 110 111 135 139 143 443 445 993 995 1723 3306 3389 5900 8080)

    for port in "${common_ports[@]}"; do
        timeout 1 bash -c "echo >/dev/tcp/$target/$port" 2>/dev/null && \
            echo -e "${GREEN}[+] Port $port is OPEN${NC}"
    done
    echo ""
}

##############################################
# ARP Scan Alternative
##############################################
arp_scan() {
    echo -e "${YELLOW}[+] Checking ARP table...${NC}"

    if command -v arp &> /dev/null; then
        arp -a
    elif command -v ip &> /dev/null; then
        ip neigh
    else
        echo "[!] No ARP tools available"
    fi
    echo ""
}

##############################################
# Network Interface Info
##############################################
interface_info() {
    echo -e "${YELLOW}[+] Network Interfaces:${NC}"

    if command -v ip &> /dev/null; then
        ip addr
    else
        ifconfig
    fi
    echo ""

    echo -e "${YELLOW}[+] Routing Table:${NC}"
    if command -v ip &> /dev/null; then
        ip route
    else
        route -n
    fi
    echo ""
}

##############################################
# Service Banner Grabbing
##############################################
banner_grab() {
    local target=$1
    local port=$2

    echo -e "${YELLOW}[+] Grabbing banner from $target:$port${NC}"

    timeout 3 bash -c "exec 3<>/dev/tcp/$target/$port && echo -e 'HEAD / HTTP/1.0\r\n\r\n' >&3 && cat <&3" 2>/dev/null

    echo ""
}

##############################################
# Main Menu
##############################################
main_menu() {
    echo -e "${BLUE}Select scan type:${NC}"
    echo "1) Quick network discovery (ping sweep)"
    echo "2) Scan specific host (port scan)"
    echo "3) Full network scan (discovery + port scan)"
    echo "4) ARP table lookup"
    echo "5) Interface information"
    echo "6) Custom target"
    echo ""
    read -p "Choice [1-6]: " choice

    get_local_network

    case $choice in
        1)
            ping_sweep "$network_prefix"
            ;;
        2)
            read -p "Enter target IP: " target
            port_scan "$target"
            ;;
        3)
            ping_sweep "$network_prefix"
            echo -e "${YELLOW}[+] Scanning all active hosts...${NC}"
            for host in "${active_hosts[@]}"; do
                port_scan "$host"
            done
            ;;
        4)
            arp_scan
            ;;
        5)
            interface_info
            ;;
        6)
            read -p "Enter target IP: " target
            read -p "Enter port (or 'all' for common ports): " port

            if [ "$port" = "all" ]; then
                quick_port_scan "$target"
            else
                timeout 1 bash -c "echo >/dev/tcp/$target/$port" 2>/dev/null && \
                    echo -e "${GREEN}[+] Port $port is OPEN${NC}" || \
                    echo -e "${RED}[-] Port $port is CLOSED${NC}"
            fi
            ;;
        *)
            echo -e "${RED}Invalid choice${NC}"
            exit 1
            ;;
    esac
}

##############################################
# Check for arguments
##############################################
if [ $# -eq 0 ]; then
    main_menu
else
    # Direct scan mode
    target=$1
    echo -e "${YELLOW}[+] Scanning $target...${NC}\n"
    quick_port_scan "$target"
fi

echo -e "${GREEN}[✓] Scan complete!${NC}"
echo -e "${YELLOW}Note: For advanced scanning, use nmap:${NC}"
echo "  nmap -sn $network_prefix.0/24        # Ping sweep"
echo "  nmap -p- $target                     # All ports"
echo "  nmap -sV -sC $target                 # Version & scripts"
echo ""
