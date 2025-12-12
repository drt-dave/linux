#!/bin/bash

##############################################
# Simple Web Crawler & Enumeration Tool
# Purpose: Discover web pages, forms, and parameters
# Use: For authorized web application testing only
##############################################

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════╗"
echo "║       WEB CRAWLER & ENUMERATOR            ║"
echo "║       For Authorized Testing Only         ║"
echo "╚═══════════════════════════════════════════╝"
echo -e "${NC}\n"

# Check for required tools
if ! command -v curl &> /dev/null; then
    echo -e "${RED}[!] curl is required but not installed${NC}"
    exit 1
fi

# Variables
TARGET=""
OUTPUT_DIR="web_enum_$(date +%Y%m%d_%H%M%S)"
MAX_DEPTH=2
FOUND_URLS=()
FOUND_FORMS=()
FOUND_PARAMS=()

##############################################
# Functions
##############################################

usage() {
    echo "Usage: $0 -u <URL> [-d depth]"
    echo ""
    echo "Options:"
    echo "  -u    Target URL (required)"
    echo "  -d    Max crawl depth (default: 2)"
    echo ""
    echo "Example: $0 -u http://example.com -d 3"
    exit 1
}

# Extract links from HTML
extract_links() {
    local url=$1
    local html=$2

    # Extract href attributes
    echo "$html" | grep -oP '(?<=href=")[^"]*' | while read -r link; do
        # Convert relative to absolute URLs
        if [[ $link == http* ]]; then
            echo "$link"
        elif [[ $link == /* ]]; then
            echo "${url}${link}"
        elif [[ $link != "#"* ]] && [[ $link != "javascript:"* ]]; then
            echo "${url}/${link}"
        fi
    done
}

# Extract forms
extract_forms() {
    local html=$1

    # Simple form detection
    echo "$html" | grep -i "<form" | while read -r form; do
        action=$(echo "$form" | grep -oP '(?<=action=")[^"]*' | head -1)
        method=$(echo "$form" | grep -oP '(?<=method=")[^"]*' | head -1)
        echo "Form: Action=$action Method=$method"
    done
}

# Extract parameters from URL
extract_params() {
    local url=$1

    if [[ $url == *"?"* ]]; then
        params=$(echo "$url" | cut -d'?' -f2)
        IFS='&' read -ra PARAM_ARRAY <<< "$params"
        for param in "${PARAM_ARRAY[@]}"; do
            param_name=$(echo "$param" | cut -d'=' -f1)
            echo "$param_name"
        done
    fi
}

# Crawl function
crawl() {
    local url=$1
    local depth=$2

    if [ $depth -gt $MAX_DEPTH ]; then
        return
    fi

    # Check if already visited
    if [[ " ${FOUND_URLS[@]} " =~ " ${url} " ]]; then
        return
    fi

    echo -e "${YELLOW}[*] Crawling: $url (depth: $depth)${NC}"

    # Add to found URLs
    FOUND_URLS+=("$url")

    # Fetch the page
    html=$(curl -s -L "$url" 2>/dev/null)

    if [ -z "$html" ]; then
        echo -e "${RED}[!] Failed to fetch $url${NC}"
        return
    fi

    # Extract and save information
    echo "$url" >> "$OUTPUT_DIR/urls.txt"

    # Find forms
    forms=$(extract_forms "$html")
    if [ -n "$forms" ]; then
        echo "$url" >> "$OUTPUT_DIR/forms.txt"
        echo "$forms" >> "$OUTPUT_DIR/forms.txt"
    fi

    # Find parameters
    params=$(extract_params "$url")
    if [ -n "$params" ]; then
        echo "$params" >> "$OUTPUT_DIR/parameters.txt"
    fi

    # Extract links and crawl recursively
    links=$(extract_links "$url" "$html")

    while IFS= read -r link; do
        # Only crawl same domain
        if [[ $link == *"$TARGET"* ]]; then
            crawl "$link" $((depth + 1))
        fi
    done <<< "$links"
}

# Technology detection
detect_tech() {
    local url=$1

    echo -e "${YELLOW}[+] Detecting Technologies...${NC}"

    # Fetch headers
    headers=$(curl -s -I "$url")

    echo "$headers" > "$OUTPUT_DIR/headers.txt"

    # Server
    server=$(echo "$headers" | grep -i "Server:" | cut -d: -f2-)
    if [ -n "$server" ]; then
        echo "  Server:$server"
    fi

    # Powered by
    powered_by=$(echo "$headers" | grep -i "X-Powered-By:" | cut -d: -f2-)
    if [ -n "$powered_by" ]; then
        echo "  Powered-By:$powered_by"
    fi

    # Fetch homepage
    html=$(curl -s "$url")

    # Detect CMS/Framework
    if echo "$html" | grep -qi "wordpress"; then
        echo "  CMS: WordPress detected"
    fi
    if echo "$html" | grep -qi "joomla"; then
        echo "  CMS: Joomla detected"
    fi
    if echo "$html" | grep -qi "drupal"; then
        echo "  CMS: Drupal detected"
    fi

    # Check for common files
    echo -e "\n${YELLOW}[+] Checking for common files...${NC}"

    common_files=(
        "robots.txt"
        "sitemap.xml"
        ".git/config"
        ".env"
        "config.php"
        "phpinfo.php"
        "admin"
        "login"
        "wp-admin"
    )

    for file in "${common_files[@]}"; do
        status=$(curl -s -o /dev/null -w "%{http_code}" "$url/$file")
        if [ "$status" = "200" ]; then
            echo -e "${GREEN}  [200] $file${NC}"
            echo "$url/$file" >> "$OUTPUT_DIR/found_files.txt"
        fi
    done
}

# Directory bruteforce (basic)
dir_enum() {
    local url=$1

    echo -e "\n${YELLOW}[+] Basic Directory Enumeration...${NC}"

    common_dirs=(
        "admin"
        "administrator"
        "login"
        "panel"
        "dashboard"
        "backup"
        "uploads"
        "images"
        "assets"
        "css"
        "js"
        "api"
        "v1"
        "test"
        "dev"
    )

    for dir in "${common_dirs[@]}"; do
        status=$(curl -s -o /dev/null -w "%{http_code}" "$url/$dir")
        if [ "$status" = "200" ] || [ "$status" = "301" ] || [ "$status" = "302" ]; then
            echo -e "${GREEN}  [$status] /$dir${NC}"
            echo "$url/$dir" >> "$OUTPUT_DIR/directories.txt"
        fi
    done
}

##############################################
# Main
##############################################

# Parse arguments
while getopts "u:d:h" opt; do
    case $opt in
        u) TARGET=$OPTARG ;;
        d) MAX_DEPTH=$OPTARG ;;
        h) usage ;;
        *) usage ;;
    esac
done

if [ -z "$TARGET" ]; then
    usage
fi

# Extract base domain
BASE_URL=$(echo "$TARGET" | grep -oP 'https?://[^/]+')

echo -e "${GREEN}[+] Target: $TARGET${NC}"
echo -e "${GREEN}[+] Base URL: $BASE_URL${NC}"
echo -e "${GREEN}[+] Max Depth: $MAX_DEPTH${NC}\n"

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Detect technologies
detect_tech "$TARGET"

# Directory enumeration
dir_enum "$BASE_URL"

# Start crawling
echo -e "\n${YELLOW}[+] Starting crawl...${NC}\n"
crawl "$TARGET" 0

# Generate report
echo -e "\n${BLUE}╔═══════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║              CRAWL COMPLETE               ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════╝${NC}\n"

{
    echo "=== WEB ENUMERATION REPORT ==="
    echo "Target: $TARGET"
    echo "Date: $(date)"
    echo ""
    echo "=== STATISTICS ==="
    echo "URLs Found: $(cat "$OUTPUT_DIR/urls.txt" 2>/dev/null | wc -l)"
    echo "Forms Found: $(cat "$OUTPUT_DIR/forms.txt" 2>/dev/null | grep "Form:" | wc -l)"
    echo "Parameters Found: $(cat "$OUTPUT_DIR/parameters.txt" 2>/dev/null | sort -u | wc -l)"
    echo "Directories Found: $(cat "$OUTPUT_DIR/directories.txt" 2>/dev/null | wc -l)"
    echo ""
    echo "=== OUTPUT FILES ==="
    ls -lh "$OUTPUT_DIR"
} | tee "$OUTPUT_DIR/REPORT.txt"

echo -e "\n${GREEN}[✓] Results saved in: $OUTPUT_DIR${NC}"
echo -e "${YELLOW}[*] For advanced crawling, use:${NC}"
echo "  - Burp Suite Spider"
echo "  - OWASP ZAP Spider"
echo "  - gospider"
echo ""
