#!/bin/bash

# DNS Enumeration Tool
# Perform comprehensive DNS reconnaissance

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
echo "========================================"
echo "    DNS Enumeration Tool v1.0"
echo "========================================"
echo -e "${NC}"

if [ -z "$1" ]; then
    echo -e "${RED}[!] Usage: $0 <domain>${NC}"
    echo "Example: $0 example.com"
    exit 1
fi

DOMAIN=$1

echo -e "${YELLOW}[*] Target domain: $DOMAIN${NC}"
echo ""

# Output file
OUTPUT="dns_enum_${DOMAIN}_$(date +%Y%m%d_%H%M%S).txt"

# Function to run dig queries
query_dns() {
    RECORD_TYPE=$1
    echo -e "${BLUE}[*] Querying $RECORD_TYPE records...${NC}"
    dig $DOMAIN $RECORD_TYPE +short | tee -a $OUTPUT
    echo ""
}

# Basic DNS lookup
echo -e "${YELLOW}[*] Basic DNS Information${NC}"
echo "========================================" | tee -a $OUTPUT

# A records (IPv4)
echo -e "${BLUE}[*] A Records (IPv4):${NC}"
dig $DOMAIN A +short | tee -a $OUTPUT
echo ""

# AAAA records (IPv6)
echo -e "${BLUE}[*] AAAA Records (IPv6):${NC}"
dig $DOMAIN AAAA +short | tee -a $OUTPUT
echo ""

# MX records (Mail servers)
echo -e "${BLUE}[*] MX Records (Mail Servers):${NC}"
dig $DOMAIN MX +short | tee -a $OUTPUT
echo ""

# NS records (Name servers)
echo -e "${BLUE}[*] NS Records (Name Servers):${NC}"
NS_SERVERS=$(dig $DOMAIN NS +short)
echo "$NS_SERVERS" | tee -a $OUTPUT
echo ""

# TXT records
echo -e "${BLUE}[*] TXT Records:${NC}"
dig $DOMAIN TXT +short | tee -a $OUTPUT
echo ""

# SOA record
echo -e "${BLUE}[*] SOA Record:${NC}"
dig $DOMAIN SOA +short | tee -a $OUTPUT
echo ""

# CNAME records
echo -e "${BLUE}[*] CNAME Records:${NC}"
dig $DOMAIN CNAME +short | tee -a $OUTPUT
echo ""

# Attempt zone transfer
echo -e "${YELLOW}[*] Attempting Zone Transfer...${NC}"
echo "========================================" | tee -a $OUTPUT

ZONE_TRANSFER_SUCCESS=0
for NS in $NS_SERVERS; do
    echo -e "${BLUE}[*] Trying zone transfer from: $NS${NC}"
    ZT_RESULT=$(dig @$NS $DOMAIN AXFR +short 2>&1)

    if echo "$ZT_RESULT" | grep -q "Transfer failed" || [ -z "$ZT_RESULT" ]; then
        echo -e "${RED}[!] Zone transfer failed on $NS${NC}"
    else
        echo -e "${GREEN}[+] Zone transfer successful on $NS!${NC}"
        echo "$ZT_RESULT" | tee -a $OUTPUT
        ZONE_TRANSFER_SUCCESS=1
    fi
    echo ""
done

if [ $ZONE_TRANSFER_SUCCESS -eq 0 ]; then
    echo -e "${YELLOW}[*] Zone transfer not allowed (this is normal)${NC}"
fi
echo ""

# Common subdomain enumeration
echo -e "${YELLOW}[*] Enumerating Common Subdomains...${NC}"
echo "========================================" | tee -a $OUTPUT

SUBDOMAINS=("www" "mail" "ftp" "localhost" "webmail" "smtp" "pop" "ns1" "ns2" "admin" "vpn" "ssh" "remote" "dev" "staging" "api" "cdn" "blog" "shop" "portal")

FOUND_SUBDOMAINS=0
for SUB in "${SUBDOMAINS[@]}"; do
    RESULT=$(dig ${SUB}.${DOMAIN} A +short 2>/dev/null)
    if [ ! -z "$RESULT" ]; then
        echo -e "${GREEN}[+] Found: ${SUB}.${DOMAIN} -> $RESULT${NC}"
        echo "${SUB}.${DOMAIN} -> $RESULT" >> $OUTPUT
        FOUND_SUBDOMAINS=$((FOUND_SUBDOMAINS + 1))
    fi
done

echo ""
echo -e "${GREEN}[+] Found $FOUND_SUBDOMAINS subdomains${NC}"
echo ""

# Reverse DNS lookup
echo -e "${YELLOW}[*] Reverse DNS Lookups...${NC}"
echo "========================================" | tee -a $OUTPUT

IPS=$(dig $DOMAIN A +short)
for IP in $IPS; do
    echo -e "${BLUE}[*] Reverse lookup for $IP:${NC}"
    dig -x $IP +short | tee -a $OUTPUT
    echo ""
done

# SPF record check
echo -e "${YELLOW}[*] Checking SPF Records (Email Security)...${NC}"
SPF=$(dig $DOMAIN TXT +short | grep "v=spf1")
if [ ! -z "$SPF" ]; then
    echo -e "${GREEN}[+] SPF Record found:${NC}"
    echo "$SPF"
else
    echo -e "${RED}[!] No SPF record found (email spoofing possible)${NC}"
fi
echo ""

# DMARC record check
echo -e "${YELLOW}[*] Checking DMARC Records...${NC}"
DMARC=$(dig _dmarc.$DOMAIN TXT +short | grep "v=DMARC1")
if [ ! -z "$DMARC" ]; then
    echo -e "${GREEN}[+] DMARC Record found:${NC}"
    echo "$DMARC"
else
    echo -e "${RED}[!] No DMARC record found${NC}"
fi
echo ""

# Summary
echo -e "${GREEN}[+] DNS Enumeration Complete${NC}"
echo -e "${YELLOW}[*] Results saved to: $OUTPUT${NC}"
echo ""
echo -e "${BLUE}[*] Scan completed at $(date)${NC}"
