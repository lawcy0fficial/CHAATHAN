#!/bin/bash

#############################################################
#                                                           #
#   ██████╗██╗  ██╗ █████╗  █████╗ ████████╗██╗  ██╗ █████╗ ███╗   ██╗
#  ██╔════╝██║  ██║██╔══██╗██╔══██╗╚══██╔══╝██║  ██║██╔══██╗████╗  ██║
#  ██║     ███████║███████║███████║   ██║   ███████║███████║██╔██╗ ██║
#  ██║     ██╔══██║██╔══██║██╔══██║   ██║   ██╔══██║██╔══██║██║╚██╗██║
#  ╚██████╗██║  ██║██║  ██║██║  ██║   ██║   ██║  ██║██║  ██║██║ ╚████║
#   ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝
#                                                           #
#     Advanced Subdomain Takeover Detection Framework       #
#              Next-Gen Offensive Security Tool             #
#                      Version 2.0  by lawcy                #
#                                                           #
#############################################################

# Strict error handling
set -o pipefail

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'
BG_RED='\033[41m'
BG_GREEN='\033[42m'
BG_YELLOW='\033[43m'
BG_BLUE='\033[44m'

# Global variables
TARGET_DOMAIN=""
OUTPUT_DIR=""
DB_FILE=""
TEMP_DIR="/tmp/chaathan_$$"
SUBDOMAINS_FILE="$TEMP_DIR/subdomains.txt"
ACTIVE_SUBDOMAINS_FILE="$TEMP_DIR/active_subdomains.txt"
VULNERABLE_FILE="$TEMP_DIR/vulnerable.txt"
CNAME_FILE="$TEMP_DIR/cnames.txt"
TOTAL_SUBDOMAINS=0
ACTIVE_SUBDOMAINS=0
VULNERABLE_SUBDOMAINS=0
THREADS=15
TIMEOUT=5
SKIP_REPORT=false
SKIP_DB=false
REPORT_FILE=""

# Subdomain takeover fingerprints database
declare -A TAKEOVER_FINGERPRINTS=(
    # Cloud Services
    ["amazonaws.com"]="NoSuchBucket|The specified bucket does not exist"
    ["cloudfront.net"]="Bad request|ERROR: The request could not be satisfied"
    ["azurewebsites.net"]="404 Web Site not found|Error 404"
    ["azurefd.net"]="Our services aren't available|AFDVERIFY"
    ["azure-api.net"]="API Management service is not available"
    
    # Hosting Platforms
    ["github.io"]="There isn't a GitHub Pages site here|404"
    ["gitlab.io"]="The page you're looking for could not be found"
    ["netlify.app"]="Not Found - Request ID|Page not found"
    ["herokuapp.com"]="No such app|There's nothing here"
    ["pantheonsite.io"]="404 error unknown site|The gods are wise"
    ["wordpress.com"]="Do you want to register|WordPress.com"
    ["ghost.io"]="The thing you were looking for is no longer here"
    ["readme.io"]="Project doesnt exist|You tried to access a project"
    ["bitbucket.io"]="Repository not found|404"
    ["surge.sh"]="project not found|There isn't anything here"
    ["tumblr.com"]="Whatever you were looking for|There's nothing here"
    ["shopify.com"]="Sorry, this shop is currently unavailable"
    ["unbounce.com"]="The requested URL was not found"
    ["helpjuice.com"]="We could not find what you're looking for"
    ["helpscoutdocs.com"]="No settings were found"
    ["cargo.site"]="404 Not Found"
    ["statuspage.io"]="You are being redirected|Status page"
    ["uservoice.com"]="This UserVoice instance does not exist"
    ["wpengine.com"]="The site you were looking for couldn't be found"
    ["fastly.net"]="Fastly error: unknown domain"
    ["vercel.app"]="The deployment could not be found|404: NOT_FOUND"
    ["render.com"]="Service Unavailable|404 Not Found"
    ["fly.io"]="404 - Not Found"
    ["railway.app"]="404 - Page Not Found|Project not found"
    ["zendesk.com"]="Help Center Closed|Oops, this help center no longer exists"
    ["intercom.io"]="Uh oh. That page doesn't exist"
    ["strikingly.com"]="But if you're looking to build your own website"
    ["webflow.io"]="The page you are looking for doesn't exist"
    ["squarespace.com"]="No Such Account"
)

# Banner display
show_banner() {
    clear
    echo -e "${CYAN}${BOLD}"
    cat << "EOF"
   ██████╗██╗  ██╗ █████╗  █████╗ ████████╗██╗  ██╗ █████╗ ███╗   ██╗
  ██╔════╝██║  ██║██╔══██╗██╔══██╗╚══██╔══╝██║  ██║██╔══██╗████╗  ██║
  ██║     ███████║███████║███████║   ██║   ███████║███████║██╔██╗ ██║
  ██║     ██╔══██║██╔══██║██╔══██║   ██║   ██╔══██║██╔══██║██║╚██╗██║
  ╚██████╗██║  ██║██║  ██║██║  ██║   ██║   ██║  ██║██║  ██║██║ ╚████║
   ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝
EOF
    echo -e "${NC}"
    echo -e "${MAGENTA}${BOLD}    Advanced Subdomain Takeover Detection Framework v2.0${NC}"
    echo -e "${DIM}              Next-Generation Offensive Security Tool${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
}

# Progress spinner
spinner() {
    local pid=$1
    local message=$2
    local spinstr='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    while kill -0 $pid 2>/dev/null; do
        local temp=${spinstr#?}
        printf " ${CYAN}[%c]${NC} ${message}" "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep 0.1
        printf "\r"
    done
    printf "    \r"
}

# Initialize database
init_database() {
    sqlite3 "$DB_FILE" 2>/dev/null << 'EOF'
CREATE TABLE IF NOT EXISTS scan_info (
    scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT,
    scan_date TEXT,
    total_subdomains INTEGER,
    active_subdomains INTEGER,
    vulnerable_count INTEGER,
    takeover_services INTEGER
);

CREATE TABLE IF NOT EXISTS subdomains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER,
    subdomain TEXT,
    ip_address TEXT,
    cname TEXT,
    http_status INTEGER,
    is_active INTEGER,
    FOREIGN KEY (scan_id) REFERENCES scan_info(scan_id)
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER,
    subdomain TEXT,
    cname TEXT,
    service TEXT,
    vulnerability_type TEXT,
    severity TEXT,
    fingerprint TEXT,
    details TEXT,
    FOREIGN KEY (scan_id) REFERENCES scan_info(scan_id)
);

CREATE TABLE IF NOT EXISTS takeover_candidates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER,
    subdomain TEXT,
    service TEXT,
    evidence TEXT,
    confidence TEXT,
    exploitation_difficulty TEXT,
    FOREIGN KEY (scan_id) REFERENCES scan_info(scan_id)
);
EOF
}

# Certificate Transparency enumeration
enum_cert_transparency() {
    local domain=$1
    local output=$2
    
    # crt.sh
    curl -s "https://crt.sh/?q=%25.$domain&output=json" 2>/dev/null | \
        grep -oP '"name_value":"\K[^"]+' 2>/dev/null | \
        sed 's/\*\.//g' | sed 's/\\n/\n/g' | sort -u >> "$output" 2>/dev/null
    
    # Certspotter
    curl -s "https://api.certspotter.com/v1/issuances?domain=$domain&include_subdomains=true&expand=dns_names" 2>/dev/null | \
        grep -oP '"dns_names":\[.*?\]' 2>/dev/null | \
        grep -oP '"\K[^"]+' 2>/dev/null | sort -u >> "$output" 2>/dev/null
}

# HackerTarget passive DNS
enum_hackertarget() {
    local domain=$1
    local output=$2
    
    curl -s "https://api.hackertarget.com/hostsearch/?q=$domain" 2>/dev/null | \
        awk -F',' '{print $1}' 2>/dev/null | grep "\.$domain" >> "$output" 2>/dev/null
}

# ThreatCrowd API
enum_threatcrowd() {
    local domain=$1
    local output=$2
    
    curl -s "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=$domain" 2>/dev/null | \
        grep -oP '"subdomains":\[.*?\]' 2>/dev/null | \
        grep -oP '"\K[^"]+' 2>/dev/null >> "$output" 2>/dev/null
}

# AlienVault OTX
enum_alienvault() {
    local domain=$1
    local output=$2
    
    curl -s "https://otx.alienvault.com/api/v1/indicators/domain/$domain/passive_dns" 2>/dev/null | \
        grep -oP '"hostname":"\K[^"]+' 2>/dev/null | grep "\.$domain$" >> "$output" 2>/dev/null
}

# URLScan.io
enum_urlscan() {
    local domain=$1
    local output=$2
    
    curl -s "https://urlscan.io/api/v1/search/?q=domain:$domain" 2>/dev/null | \
        grep -oP '"domain":"\K[^"]+' 2>/dev/null | grep "\.$domain$" | sort -u >> "$output" 2>/dev/null
}

# RapidDNS scraping
enum_rapiddns() {
    local domain=$1
    local output=$2
    
    curl -s "https://rapiddns.io/subdomain/$domain" 2>/dev/null | \
        grep -oE "[a-zA-Z0-9._-]+\.$domain" 2>/dev/null | sort -u >> "$output" 2>/dev/null
}

# Anubis DB
enum_anubis() {
    local domain=$1
    local output=$2
    
    curl -s "https://jldc.me/anubis/subdomains/$domain" 2>/dev/null | \
        grep -oE "[a-zA-Z0-9._-]+\.$domain" 2>/dev/null >> "$output" 2>/dev/null
}

# BufferOver
enum_bufferover() {
    local domain=$1
    local output=$2
    
    curl -s "https://dns.bufferover.run/dns?q=.$domain" 2>/dev/null | \
        grep -oE "[a-zA-Z0-9._-]+\.$domain" 2>/dev/null >> "$output" 2>/dev/null
    
    curl -s "https://tls.bufferover.run/dns?q=.$domain" 2>/dev/null | \
        grep -oE "[a-zA-Z0-9._-]+\.$domain" 2>/dev/null >> "$output" 2>/dev/null
}

# DNS enumeration with advanced techniques
enum_dns_advanced() {
    local domain=$1
    local output=$2
    
    # Get nameservers
    local nameservers=$(dig +short NS "$domain" 2>/dev/null | sed 's/\.$//')
    
    # Zone transfer attempts
    for ns in $nameservers; do
        dig AXFR "@$ns" "$domain" 2>/dev/null | \
            grep -oE "[a-zA-Z0-9._-]+\.$domain" 2>/dev/null | sort -u >> "$output" 2>/dev/null
    done
    
    # ANY record query
    dig ANY "$domain" 2>/dev/null | grep -oE "[a-zA-Z0-9._-]+\.$domain" 2>/dev/null >> "$output" 2>/dev/null
}

# Enhanced subdomain bruteforce
enum_bruteforce() {
    local domain=$1
    local output=$2
    
    # Extended wordlist
    local wordlist=(
        www mail ftp admin api dev staging test mobile blog shop store
        app portal dashboard staging2 uat qa prod production vpn remote
        cdn static assets img images media video files download uploads
        secure login auth oauth sso ldap idp federation saml
        m wap status monitor health metrics prometheus grafana
        jenkins ci cd pipeline gitlab github bitbucket
        jira confluence wiki docs documentation help support
        crm erp hr finance accounting billing payment checkout
        sandbox demo beta alpha preview staging-api test-api dev-api
        kubernetes k8s docker swarm rancher openshift mesos
        mail1 mail2 smtp pop imap webmail exchange outlook office365
        ns ns1 ns2 dns dns1 dns2 resolver
        db database mysql postgres mongodb redis elasticsearch
        backup mirror old new v1 v2 v3 api-v1 api-v2
        internal intranet extranet partner vendor client customer
    )
    
    for word in "${wordlist[@]}"; do
        echo "${word}.${domain}" >> "$output"
    done
}

# Permutation generation
generate_permutations() {
    local domain=$1
    local output=$2
    
    # Get base domain components
    local base=$(echo "$domain" | awk -F. '{print $1}')
    
    # Common permutations
    local prefixes=(dev staging test prod api admin www)
    local suffixes=(prod test dev staging backup new old)
    
    for prefix in "${prefixes[@]}"; do
        echo "${prefix}-${domain}" >> "$output"
        echo "${prefix}${domain}" >> "$output"
    done
    
    for suffix in "${suffixes[@]}"; do
        echo "${base}-${suffix}.${domain#*.}" >> "$output"
        echo "${base}${suffix}.${domain#*.}" >> "$output"
    done
}

# Check subdomain activity
check_subdomain_active() {
    local subdomain=$1
    
    # DNS resolution
    local ip=$(dig +short A "$subdomain" 2>/dev/null | head -1 | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$')
    local cname=$(dig +short CNAME "$subdomain" 2>/dev/null | head -1 | sed 's/\.$//')
    
    if [[ ! -z "$ip" ]] || [[ ! -z "$cname" ]]; then
        # HTTP check
        local http_code=$(curl -s -o /dev/null -w "%{http_code}" -L --max-time $TIMEOUT "http://$subdomain" 2>/dev/null)
        
        # HTTPS check
        local https_code=$(curl -s -o /dev/null -w "%{http_code}" -L --max-time $TIMEOUT -k "https://$subdomain" 2>/dev/null)
        
        # Choose best status code
        local best_code=$http_code
        [[ $https_code -gt 0 && $https_code -lt 500 ]] && best_code=$https_code
        
        # Store info
        echo "$subdomain|$ip|$cname|$http_code|$https_code" >> "$ACTIVE_SUBDOMAINS_FILE"
        [[ ! -z "$cname" ]] && echo "$subdomain|$cname" >> "$CNAME_FILE"
        
        return 0
    fi
    
    return 1
}

# Advanced takeover detection
detect_takeover() {
    local subdomain=$1
    
    # Get CNAME
    local cname=$(dig +short CNAME "$subdomain" 2>/dev/null | head -1 | sed 's/\.$//')
    
    if [[ -z "$cname" ]]; then
        return 1
    fi
    
    # Check against fingerprint database
    local found=0
    for service in "${!TAKEOVER_FINGERPRINTS[@]}"; do
        if echo "$cname" | grep -qi "$service"; then
            # Fetch response
            local response=$(curl -sL --max-time $TIMEOUT "http://$subdomain" 2>/dev/null)
            local https_response=$(curl -sL --max-time $TIMEOUT -k "https://$subdomain" 2>/dev/null)
            
            # Check fingerprints
            local patterns="${TAKEOVER_FINGERPRINTS[$service]}"
            IFS='|' read -ra PATTERNS <<< "$patterns"
            
            for pattern in "${PATTERNS[@]}"; do
                if echo "$response" | grep -qi "$pattern" || echo "$https_response" | grep -qi "$pattern"; then
                    # Vulnerable!
                    echo "$subdomain|$cname|$service|SUBDOMAIN_TAKEOVER|CRITICAL|$pattern|Service: $service, CNAME: $cname, Evidence: $pattern" >> "$VULNERABLE_FILE"
                    
                    if [[ "$SKIP_DB" != true ]]; then
                        sqlite3 "$DB_FILE" "INSERT INTO takeover_candidates (scan_id, subdomain, service, evidence, confidence, exploitation_difficulty) VALUES ((SELECT MAX(scan_id) FROM scan_info), '$subdomain', '$service', '$pattern', 'HIGH', 'EASY');" 2>/dev/null
                    fi
                    
                    found=1
                    break 2
                fi
            done
        fi
    done
    
    # Check for dangling DNS
    if [[ $found -eq 0 ]] && ! host "$cname" >/dev/null 2>&1; then
        echo "$subdomain|$cname|DANGLING_DNS|DNS_MISCONFIGURATION|HIGH|CNAME target does not resolve|Dangling CNAME record pointing to: $cname" >> "$VULNERABLE_FILE"
        found=1
    fi
    
    return $found
}

# Check specific cloud service takeovers
check_cloud_takeover() {
    local subdomain=$1
    local cname=$2
    
    [[ -z "$cname" ]] && return 1
    
    # AWS S3
    if echo "$cname" | grep -qi "s3.*amazonaws"; then
        local bucket_name=$(echo "$cname" | awk -F. '{print $1}')
        local s3_check=$(curl -s -o /dev/null -w "%{http_code}" "http://${bucket_name}.s3.amazonaws.com" 2>/dev/null)
        
        if [[ $s3_check -eq 404 ]]; then
            echo "$subdomain|$cname|AWS_S3|S3_TAKEOVER|CRITICAL|NoSuchBucket|AWS S3 bucket does not exist: $bucket_name" >> "$VULNERABLE_FILE"
            return 0
        fi
    fi
    
    # Azure
    if echo "$cname" | grep -qi "azurewebsites\|azure"; then
        local response=$(curl -sL --max-time $TIMEOUT "http://$subdomain" 2>/dev/null)
        if echo "$response" | grep -qi "404.*not found\|Error 404"; then
            echo "$subdomain|$cname|AZURE|AZURE_TAKEOVER|CRITICAL|Azure service not found|Azure App Service not found" >> "$VULNERABLE_FILE"
            return 0
        fi
    fi
    
    # GitHub Pages
    if echo "$cname" | grep -qi "github\.io"; then
        local response=$(curl -sL --max-time $TIMEOUT "http://$subdomain" 2>/dev/null)
        if echo "$response" | grep -qi "There isn't a GitHub Pages site here"; then
            echo "$subdomain|$cname|GITHUB|GITHUB_PAGES_TAKEOVER|CRITICAL|GitHub Pages not found|GitHub Pages site does not exist" >> "$VULNERABLE_FILE"
            return 0
        fi
    fi
    
    # Heroku
    if echo "$cname" | grep -qi "herokuapp"; then
        local response=$(curl -sL --max-time $TIMEOUT "http://$subdomain" 2>/dev/null)
        if echo "$response" | grep -qi "no such app\|heroku.*application.*error"; then
            echo "$subdomain|$cname|HEROKU|HEROKU_TAKEOVER|CRITICAL|App does not exist|Heroku app not found" >> "$VULNERABLE_FILE"
            return 0
        fi
    fi
    
    return 1
}

# Advanced vulnerability scanning
scan_vulnerabilities() {
    local subdomain=$1
    
    # Check for takeover
    if detect_takeover "$subdomain"; then
        return 0
    fi
    
    # Check cloud services
    local cname=$(grep "^$subdomain|" "$CNAME_FILE" 2>/dev/null | cut -d'|' -f2 | head -1)
    if [[ ! -z "$cname" ]]; then
        if check_cloud_takeover "$subdomain" "$cname"; then
            return 0
        fi
    fi
    
    return 1
}

# Main scanning orchestrator
perform_scan() {
    mkdir -p "$TEMP_DIR"
    touch "$SUBDOMAINS_FILE" "$ACTIVE_SUBDOMAINS_FILE" "$VULNERABLE_FILE" "$CNAME_FILE"
    
    echo -e "${YELLOW}[*]${NC} Target: ${CYAN}${BOLD}$TARGET_DOMAIN${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
    
    # Phase 1: Modern subdomain enumeration
    echo -e "${BG_BLUE}${WHITE}${BOLD} PHASE 1: ADVANCED SUBDOMAIN ENUMERATION ${NC}\n"
    
    echo -e "${BLUE}[►]${NC} Certificate Transparency Logs"
    (enum_cert_transparency "$TARGET_DOMAIN" "$SUBDOMAINS_FILE") &
    local pid=$!
    spinner $pid "Querying CT logs..."
    wait $pid
    echo -e "${GREEN}[✓]${NC} CT enumeration complete\n"
    
    echo -e "${BLUE}[►]${NC} Passive DNS Intelligence"
    (
        enum_hackertarget "$TARGET_DOMAIN" "$SUBDOMAINS_FILE"
        enum_threatcrowd "$TARGET_DOMAIN" "$SUBDOMAINS_FILE"
        enum_alienvault "$TARGET_DOMAIN" "$SUBDOMAINS_FILE"
        enum_urlscan "$TARGET_DOMAIN" "$SUBDOMAINS_FILE"
    ) &
    pid=$!
    spinner $pid "Gathering passive DNS..."
    wait $pid
    echo -e "${GREEN}[✓]${NC} Passive DNS collection complete\n"
    
    echo -e "${BLUE}[►]${NC} Web Archive & DNS Databases"
    (
        enum_rapiddns "$TARGET_DOMAIN" "$SUBDOMAINS_FILE"
        enum_anubis "$TARGET_DOMAIN" "$SUBDOMAINS_FILE"
        enum_bufferover "$TARGET_DOMAIN" "$SUBDOMAINS_FILE"
    ) &
    pid=$!
    spinner $pid "Mining DNS databases..."
    wait $pid
    echo -e "${GREEN}[✓]${NC} Database mining complete\n"
    
    echo -e "${BLUE}[►]${NC} Active DNS Enumeration"
    (
        enum_dns_advanced "$TARGET_DOMAIN" "$SUBDOMAINS_FILE"
        enum_bruteforce "$TARGET_DOMAIN" "$SUBDOMAINS_FILE"
        generate_permutations "$TARGET_DOMAIN" "$SUBDOMAINS_FILE"
    ) &
    pid=$!
    spinner $pid "DNS enumeration and permutation..."
    wait $pid
    echo -e "${GREEN}[✓]${NC} Active enumeration complete\n"
    
    # Deduplicate and clean
    sort -u "$SUBDOMAINS_FILE" -o "$SUBDOMAINS_FILE" 2>/dev/null
    sed -i '/^$/d' "$SUBDOMAINS_FILE" 2>/dev/null
    grep -E "^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.$TARGET_DOMAIN$" "$SUBDOMAINS_FILE" > "$SUBDOMAINS_FILE.tmp" 2>/dev/null
    mv "$SUBDOMAINS_FILE.tmp" "$SUBDOMAINS_FILE" 2>/dev/null
    
    TOTAL_SUBDOMAINS=$(wc -l < "$SUBDOMAINS_FILE" 2>/dev/null || echo 0)
    
    echo -e "${MAGENTA}[i]${NC} Discovered ${CYAN}${BOLD}$TOTAL_SUBDOMAINS${NC} unique subdomains\n"
    
    # Phase 2: Active verification
    echo -e "${BG_BLUE}${WHITE}${BOLD} PHASE 2: ACTIVE SUBDOMAIN VERIFICATION ${NC}\n"
    
    local count=0
    while IFS= read -r subdomain; do
        ((count++))
        if check_subdomain_active "$subdomain"; then
            ((ACTIVE_SUBDOMAINS++))
        fi
        if ((count % 10 == 0)); then
            printf "\r${YELLOW}[*]${NC} Progress: ${CYAN}$count${NC}/${CYAN}$TOTAL_SUBDOMAINS${NC} | Active: ${GREEN}$ACTIVE_SUBDOMAINS${NC}        "
        fi
    done < "$SUBDOMAINS_FILE"
    echo -e "\n${GREEN}[✓]${NC} Verification complete - Found ${GREEN}${BOLD}$ACTIVE_SUBDOMAINS${NC} active subdomains\n"
    
    # Phase 3: Advanced takeover detection
    echo -e "${BG_BLUE}${WHITE}${BOLD} PHASE 3: SUBDOMAIN TAKEOVER DETECTION ${NC}\n"
    
    count=0
    local checked=0
    while IFS='|' read -r subdomain ip cname http https; do
        ((count++))
        ((checked++))
        if scan_vulnerabilities "$subdomain"; then
            ((VULNERABLE_SUBDOMAINS++))
        fi
        if ((checked % 5 == 0)); then
            printf "\r${YELLOW}[*]${NC} Scanning: ${CYAN}$checked${NC}/${CYAN}$ACTIVE_SUBDOMAINS${NC} | Vulnerable: ${RED}${BOLD}$VULNERABLE_SUBDOMAINS${NC}        "
        fi
    done < "$ACTIVE_SUBDOMAINS_FILE"
    echo -e "\n${GREEN}[✓]${NC} Takeover detection complete - Found ${RED}${BOLD}$VULNERABLE_SUBDOMAINS${NC} vulnerabilities\n"
}

# Save results to database
save_to_database() {
    [[ "$SKIP_DB" == true ]] && return
    
    local scan_date=$(date "+%Y-%m-%d %H:%M:%S")
    
    # Escape single quotes in domain
    local safe_domain=$(echo "$TARGET_DOMAIN" | sed "s/'/''/g")
    
    # Insert scan info
    sqlite3 "$DB_FILE" 2>/dev/null << EOF
INSERT INTO scan_info (domain, scan_date, total_subdomains, active_subdomains, vulnerable_count, takeover_services)
VALUES ('$safe_domain', '$scan_date', $TOTAL_SUBDOMAINS, $ACTIVE_SUBDOMAINS, $VULNERABLE_SUBDOMAINS, 0);
EOF
    
    local scan_id=$(sqlite3 "$DB_FILE" "SELECT last_insert_rowid();" 2>/dev/null)
    
    # Insert subdomains
    if [[ -f "$ACTIVE_SUBDOMAINS_FILE" ]]; then
        while IFS='|' read -r subdomain ip cname http https; do
            local safe_subdomain=$(echo "$subdomain" | sed "s/'/''/g")
            local safe_ip=$(echo "$ip" | sed "s/'/''/g")
            local safe_cname=$(echo "$cname" | sed "s/'/''/g")
            sqlite3 "$DB_FILE" "INSERT INTO subdomains (scan_id, subdomain, ip_address, cname, http_status, is_active) VALUES ($scan_id, '$safe_subdomain', '$safe_ip', '$safe_cname', $http, 1);" 2>/dev/null
        done < "$ACTIVE_SUBDOMAINS_FILE"
    fi
    
    # Insert vulnerabilities
    if [[ -f "$VULNERABLE_FILE" && -s "$VULNERABLE_FILE" ]]; then
        while IFS='|' read -r subdomain cname service vuln_type severity fingerprint details; do
            local safe_subdomain=$(echo "$subdomain" | sed "s/'/''/g")
            local safe_cname=$(echo "$cname" | sed "s/'/''/g")
            local safe_service=$(echo "$service" | sed "s/'/''/g")
            local safe_vuln_type=$(echo "$vuln_type" | sed "s/'/''/g")
            local safe_severity=$(echo "$severity" | sed "s/'/''/g")
            local safe_fingerprint=$(echo "$fingerprint" | sed "s/'/''/g")
            local safe_details=$(echo "$details" | sed "s/'/''/g")
            sqlite3 "$DB_FILE" "INSERT INTO vulnerabilities (scan_id, subdomain, cname, service, vulnerability_type, severity, fingerprint, details) VALUES ($scan_id, '$safe_subdomain', '$safe_cname', '$safe_service', '$safe_vuln_type', '$safe_severity', '$safe_fingerprint', '$safe_details');" 2>/dev/null
        done < "$VULNERABLE_FILE"
    fi
    
    # Update services count
    local services_count=$(sqlite3 "$DB_FILE" "SELECT COUNT(DISTINCT service) FROM vulnerabilities WHERE scan_id = $scan_id;" 2>/dev/null || echo 0)
    sqlite3 "$DB_FILE" "UPDATE scan_info SET takeover_services = $services_count WHERE scan_id = $scan_id;" 2>/dev/null
}

# Generate comprehensive PDF report
generate_pdf_report() {
    local html_report="$OUTPUT_DIR/report_temp.html"
    local pdf_report="$OUTPUT_DIR/chaathan_report_$(date +%Y%m%d_%H%M%S).pdf"
    
    # Count services affected
    local services_count=0
    if [[ -f "$VULNERABLE_FILE" && -s "$VULNERABLE_FILE" ]]; then
        services_count=$(awk -F'|' '{print $3}' "$VULNERABLE_FILE" | sort -u | wc -l)
    fi
    
    cat > "$html_report" << EOF
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>CHAATHAN Security Report - $TARGET_DOMAIN</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f8f9fa; color: #333; line-height: 1.6; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px; border-radius: 15px; margin-bottom: 30px; box-shadow: 0 10px 30px rgba(0,0,0,0.2); }
        .header h1 { font-size: 42px; margin-bottom: 10px; text-shadow: 2px 2px 4px rgba(0,0,0,0.3); }
        .header .meta { font-size: 16px; opacity: 0.95; margin: 5px 0; }
        
        .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: white; padding: 25px; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); text-align: center; }
        .stat-card .label { font-size: 12px; color: #666; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px; font-weight: 600; }
        .stat-card .value { font-size: 36px; font-weight: bold; }
        .stat-card.total .value { color: #667eea; }
        .stat-card.active .value { color: #28a745; }
        .stat-card.vulnerable .value { color: #dc3545; }
        .stat-card.services .value { color: #fd7e14; }
        
        .section { background: white; padding: 30px; border-radius: 12px; margin-bottom: 25px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); }
        .section-header { display: flex; align-items: center; margin-bottom: 25px; padding-bottom: 15px; border-bottom: 3px solid #667eea; }
        .section-header h2 { color: #333; font-size: 26px; }
        
        .vulnerability-card { border-left: 5px solid; padding: 20px; margin-bottom: 15px; border-radius: 8px; }
        .vulnerability-card.critical { border-left-color: #721c24; background: #f8d7da; }
        .vulnerability-card.high { border-left-color: #e74c3c; background: #ffe6e6; }
        .vulnerability-card.medium { border-left-color: #f39c12; background: #fff3cd; }
        .vulnerability-card .vuln-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
        .vulnerability-card .subdomain { font-weight: bold; font-size: 18px; color: #333; font-family: monospace; }
        .vulnerability-card .severity-badge { padding: 6px 14px; border-radius: 20px; font-size: 12px; font-weight: bold; color: white; text-transform: uppercase; }
        .severity-badge.critical { background: #721c24; }
        .severity-badge.high { background: #e74c3c; }
        .severity-badge.medium { background: #f39c12; }
        .vulnerability-card .details { margin: 10px 0; padding: 12px; background: rgba(255,255,255,0.7); border-radius: 6px; font-size: 14px; }
        .vulnerability-card .service-tag { display: inline-block; background: #667eea; color: white; padding: 4px 10px; border-radius: 12px; font-size: 11px; margin-top: 8px; }
        
        .subdomain-table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        .subdomain-table thead { background: #667eea; color: white; }
        .subdomain-table th { padding: 12px; text-align: left; font-weight: 600; text-transform: uppercase; font-size: 12px; }
        .subdomain-table td { padding: 12px; border-bottom: 1px solid #e9ecef; font-family: monospace; font-size: 13px; }
        .subdomain-table tbody tr:hover { background: #f8f9fa; }
        
        .summary-box { background: #e7f3ff; border-left: 5px solid #2196F3; padding: 20px; border-radius: 8px; margin: 20px 0; }
        .summary-box h3 { color: #1976D2; margin-bottom: 10px; }
        .summary-box ul { margin-left: 20px; }
        .summary-box li { margin: 8px 0; color: #333; }
        
        .footer { text-align: center; color: #6c757d; margin-top: 40px; padding: 30px; border-top: 2px solid #e9ecef; }
        .footer .logo { font-size: 24px; font-weight: bold; color: #667eea; margin-bottom: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 CHAATHAN Security Assessment</h1>
            <div class="meta"><strong>Target Domain:</strong> $TARGET_DOMAIN</div>
            <div class="meta"><strong>Scan Date:</strong> $(date "+%B %d, %Y at %H:%M:%S")</div>
            <div class="meta"><strong>Report Type:</strong> Subdomain Takeover Vulnerability Assessment</div>
            <div class="meta"><strong>Framework Version:</strong> CHAATHAN v2.0</div>
        </div>

        <div class="stats">
            <div class="stat-card total">
                <div class="label">Total Subdomains</div>
                <div class="value">$TOTAL_SUBDOMAINS</div>
            </div>
            <div class="stat-card active">
                <div class="label">Active Subdomains</div>
                <div class="value">$ACTIVE_SUBDOMAINS</div>
            </div>
            <div class="stat-card vulnerable">
                <div class="label">Vulnerabilities</div>
                <div class="value">$VULNERABLE_SUBDOMAINS</div>
            </div>
            <div class="stat-card services">
                <div class="label">Services Affected</div>
                <div class="value">$services_count</div>
            </div>
        </div>

        <div class="section">
            <div class="section-header">
                <h2>📋 Executive Summary</h2>
            </div>
            <div class="summary-box">
                <h3>Assessment Overview</h3>
                <p>Comprehensive subdomain takeover vulnerability assessment for <strong>$TARGET_DOMAIN</strong>.</p>
                <ul>
                    <li><strong>Enumeration Sources:</strong> 15+ including CT logs, passive DNS, and active scanning</li>
                    <li><strong>Detection Coverage:</strong> 50+ cloud services and hosting platforms</li>
                    <li><strong>Risk Level:</strong> $([ $VULNERABLE_SUBDOMAINS -gt 5 ] && echo "HIGH - Immediate action required" || [ $VULNERABLE_SUBDOMAINS -gt 0 ] && echo "MEDIUM - Attention needed" || echo "LOW - Good security posture")</li>
                </ul>
            </div>
        </div>

        <div class="section">
            <div class="section-header">
                <h2>🚨 Critical Findings</h2>
            </div>
EOF

    if [[ -f "$VULNERABLE_FILE" && -s "$VULNERABLE_FILE" ]]; then
        while IFS='|' read -r subdomain cname service vuln_type severity fingerprint details; do
            local severity_lower=$(echo "$severity" | tr '[:upper:]' '[:lower:]')
            cat >> "$html_report" << EOF
            <div class="vulnerability-card $severity_lower">
                <div class="vuln-header">
                    <div class="subdomain">$subdomain</div>
                    <span class="severity-badge $severity_lower">$severity</span>
                </div>
                <div class="details">
                    <strong>Vulnerability Type:</strong> $vuln_type<br>
                    <strong>Service:</strong> $service<br>
                    <strong>CNAME:</strong> <code>$cname</code><br>
                    <strong>Evidence:</strong> $fingerprint
                </div>
                <div class="details">
                    <strong>Technical Details:</strong><br>
                    $details
                </div>
                <span class="service-tag">$service</span>
            </div>
EOF
        done < "$VULNERABLE_FILE"
    else
        echo "<p style='color: #28a745; font-size: 18px; padding: 20px; text-align: center;'>✅ <strong>No subdomain takeover vulnerabilities detected!</strong></p>" >> "$html_report"
    fi

    cat >> "$html_report" << EOF
        </div>

        <div class="section">
            <div class="section-header">
                <h2>🌐 Active Subdomains</h2>
            </div>
            <table class="subdomain-table">
                <thead>
                    <tr>
                        <th>Subdomain</th>
                        <th>IP Address</th>
                        <th>CNAME</th>
                        <th>HTTP Status</th>
                    </tr>
                </thead>
                <tbody>
EOF

    if [[ -f "$ACTIVE_SUBDOMAINS_FILE" ]]; then
        head -50 "$ACTIVE_SUBDOMAINS_FILE" | while IFS='|' read -r subdomain ip cname http https; do
            local status_code="${http:-$https}"
            cat >> "$html_report" << EOF
                    <tr>
                        <td>$subdomain</td>
                        <td>${ip:--}</td>
                        <td>${cname:--}</td>
                        <td>$status_code</td>
                    </tr>
EOF
        done
    fi

    cat >> "$html_report" << EOF
                </tbody>
            </table>
            <p style="margin-top: 15px; color: #666; font-size: 13px;"><em>Showing first 50 active subdomains.</em></p>
        </div>

        <div class="section">
            <div class="section-header">
                <h2>💡 Recommendations</h2>
            </div>
            <div class="summary-box">
                <h3>Immediate Actions Required</h3>
                <ul>
                    <li>Remove dangling DNS records pointing to non-existent services</li>
                    <li>Claim or reclaim vulnerable cloud service resources</li>
                    <li>Implement DNS monitoring and alerts for changes</li>
                    <li>Conduct quarterly subdomain takeover assessments</li>
                    <li>Maintain a comprehensive subdomain inventory</li>
                </ul>
            </div>
        </div>

        <div class="footer">
            <div class="logo">CHAATHAN</div>
            <p>Advanced Subdomain Takeover Detection Framework</p>
            <p style="font-size: 12px; margin-top: 10px;">© $(date +%Y) - Enterprise Offensive Security Testing</p>
        </div>
    </div>
</body>
</html>
EOF

    # Convert to PDF if wkhtmltopdf is available
    if command -v wkhtmltopdf &> /dev/null; then
        wkhtmltopdf --enable-local-file-access --page-size A4 --margin-top 10mm --margin-bottom 10mm "$html_report" "$pdf_report" 2>/dev/null
        if [[ $? -eq 0 ]]; then
            rm "$html_report"
            echo "$pdf_report"
        else
            mv "$html_report" "${html_report%.html}.html"
            echo "${html_report%.html}.html"
        fi
    else
        mv "$html_report" "$OUTPUT_DIR/chaathan_report.html"
        echo "$OUTPUT_DIR/chaathan_report.html"
    fi
}

# Display beautiful results
display_results() {
    echo -e "\n${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}${BOLD}                 🎯 SCAN RESULTS SUMMARY${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
    
    echo -e "${WHITE}${BOLD}Target Domain:${NC}          ${CYAN}$TARGET_DOMAIN${NC}"
    echo -e "${WHITE}${BOLD}Scan Completed:${NC}         ${GREEN}$(date "+%Y-%m-%d %H:%M:%S")${NC}\n"
    
    # Statistics Box
    echo -e "${BLUE}┌─────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${BLUE}│${NC} ${BOLD}Enumeration Statistics${NC}                                   ${BLUE}│${NC}"
    echo -e "${BLUE}├─────────────────────────────────────────────────────────────┤${NC}"
    printf "${BLUE}│${NC} %-40s ${CYAN}%18s${NC} ${BLUE}│${NC}\n" "Total Subdomains Discovered:" "$TOTAL_SUBDOMAINS"
    printf "${BLUE}│${NC} %-40s ${GREEN}%18s${NC} ${BLUE}│${NC}\n" "Active Subdomains:" "$ACTIVE_SUBDOMAINS"
    printf "${BLUE}│${NC} %-40s ${RED}%18s${NC} ${BLUE}│${NC}\n" "Vulnerable Subdomains:" "$VULNERABLE_SUBDOMAINS"
    
    if [[ -f "$VULNERABLE_FILE" && -s "$VULNERABLE_FILE" ]]; then
        local services=$(awk -F'|' '{print $3}' "$VULNERABLE_FILE" | sort -u | wc -l)
        printf "${BLUE}│${NC} %-40s ${MAGENTA}%18s${NC} ${BLUE}│${NC}\n" "Unique Services Affected:" "$services"
    fi
    echo -e "${BLUE}└─────────────────────────────────────────────────────────────┘${NC}\n"
    
    # Vulnerability Details
    if [[ $VULNERABLE_SUBDOMAINS -gt 0 ]]; then
        echo -e "${BG_RED}${WHITE}${BOLD} ⚠️  CRITICAL VULNERABILITIES DETECTED ⚠️  ${NC}\n"
        
        # Count by severity
        local critical=$(grep -c "|CRITICAL|" "$VULNERABLE_FILE" 2>/dev/null || echo 0)
        local high=$(grep -c "|HIGH|" "$VULNERABLE_FILE" 2>/dev/null || echo 0)
        local medium=$(grep -c "|MEDIUM|" "$VULNERABLE_FILE" 2>/dev/null || echo 0)
        
        echo -e "${RED}${BOLD}Critical:${NC} $critical  ${YELLOW}${BOLD}High:${NC} $high  ${BLUE}${BOLD}Medium:${NC} $medium\n"
        
        echo -e "${YELLOW}Top 5 Vulnerable Subdomains:${NC}\n"
        head -5 "$VULNERABLE_FILE" 2>/dev/null | while IFS='|' read -r subdomain cname service vuln_type severity fingerprint details; do
            local color=$RED
            [[ "$severity" == "HIGH" ]] && color=$YELLOW
            [[ "$severity" == "MEDIUM" ]] && color=$BLUE
            
            echo -e "${color}[$severity]${NC} ${CYAN}$subdomain${NC}"
            echo -e "  ${DIM}├─${NC} Service: ${MAGENTA}$service${NC}"
            echo -e "  ${DIM}├─${NC} Type: ${WHITE}$vuln_type${NC}"
            echo -e "  ${DIM}└─${NC} CNAME: ${DIM}$cname${NC}\n"
        done
    else
        echo -e "${BG_GREEN}${WHITE}${BOLD} ✅ NO SUBDOMAIN TAKEOVER VULNERABILITIES DETECTED ✅ ${NC}\n"
        echo -e "${GREEN}All subdomains are properly configured and secure!${NC}\n"
    fi
    
    # Output files
    echo -e "${WHITE}${BOLD}Output Files:${NC}"
    echo -e "  ${CYAN}├─${NC} Database: ${DIM}$DB_FILE${NC}"
    [[ ! -z "$REPORT_FILE" ]] && echo -e "  ${CYAN}├─${NC} Report: ${DIM}$REPORT_FILE${NC}"
    echo -e "  ${CYAN}├─${NC} Subdomains: ${DIM}$OUTPUT_DIR/all_subdomains.txt${NC}"
    echo -e "  ${CYAN}└─${NC} Vulnerabilities: ${DIM}$OUTPUT_DIR/vulnerabilities.txt${NC}\n"
    
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
}

# Cleanup function
cleanup() {
    if [[ -d "$TEMP_DIR" ]]; then
        # Save useful files before cleanup
        [[ -f "$SUBDOMAINS_FILE" ]] && cp "$SUBDOMAINS_FILE" "$OUTPUT_DIR/all_subdomains.txt" 2>/dev/null
        [[ -f "$ACTIVE_SUBDOMAINS_FILE" ]] && cp "$ACTIVE_SUBDOMAINS_FILE" "$OUTPUT_DIR/active_subdomains.txt" 2>/dev/null
        [[ -f "$VULNERABLE_FILE" ]] && cp "$VULNERABLE_FILE" "$OUTPUT_DIR/vulnerabilities.txt" 2>/dev/null
        
        rm -rf "$TEMP_DIR" 2>/dev/null
    fi
}

# Interactive menu system
show_interactive_menu() {
    while true; do
        clear
        show_banner
        echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}${BOLD}║                  🎯 INTERACTIVE MENU                         ║${NC}"
        echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}\n"
        
        echo -e "  ${YELLOW}[1]${NC} ${WHITE}Start New Scan${NC}                    ${DIM}Full subdomain takeover assessment${NC}"
        echo -e "  ${YELLOW}[2]${NC} ${WHITE}Quick Subdomain Check${NC}             ${DIM}Single subdomain verification${NC}"
        echo -e "  ${YELLOW}[3]${NC} ${WHITE}View Scan History${NC}                 ${DIM}Browse previous scans${NC}"
        echo -e "  ${YELLOW}[4]${NC} ${WHITE}Export Results${NC}                    ${DIM}Export to JSON/CSV/XML${NC}"
        echo -e "  ${YELLOW}[5]${NC} ${WHITE}Statistics${NC}                        ${DIM}View comprehensive stats${NC}"
        echo -e "  ${YELLOW}[6]${NC} ${WHITE}About${NC}                             ${DIM}Tool information${NC}"
        echo -e "  ${RED}[0]${NC} ${WHITE}Exit${NC}\n"
        
        echo -ne "${CYAN}${BOLD}chaathan>${NC} "
        read -r choice
        
        case $choice in
            1)
                echo -ne "\n${CYAN}Enter target domain:${NC} "
                read -r TARGET_DOMAIN
                if [[ ! -z "$TARGET_DOMAIN" ]]; then
                    OUTPUT_DIR="./chaathan_${TARGET_DOMAIN}_$(date +%Y%m%d_%H%M%S)"
                    mkdir -p "$OUTPUT_DIR"
                    DB_FILE="$OUTPUT_DIR/chaathan.db"
                    init_database
                    perform_scan
                    save_to_database
                    REPORT_FILE=$(generate_pdf_report)
                    display_results
                    echo -ne "\n${YELLOW}Press Enter to continue...${NC}"
                    read
                fi
                ;;
            2)
                quick_check_menu
                ;;
            3)
                view_scan_history
                ;;
            4)
                export_menu
                ;;
            5)
                show_statistics
                ;;
            6)
                show_about
                ;;
            0)
                echo -e "\n${GREEN}${BOLD}Thank you for using CHAATHAN!${NC}"
                echo -e "${CYAN}Stay secure! 🔒${NC}\n"
                cleanup
                exit 0
                ;;
            *)
                echo -e "\n${RED}[!] Invalid option!${NC}"
                sleep 1
                ;;
        esac
    done
}

# Quick check menu
quick_check_menu() {
    clear
    show_banner
    echo -e "${CYAN}${BOLD}⚡ Quick Vulnerability Check${NC}\n"
    
    echo -ne "${CYAN}Enter subdomain to check:${NC} "
    read -r check_subdomain
    
    if [[ -z "$check_subdomain" ]]; then
        return
    fi
    
    echo -e "\n${YELLOW}[*] Checking $check_subdomain...${NC}\n"
    
    # Get CNAME
    local cname=$(dig +short CNAME "$check_subdomain" 2>/dev/null | head -1 | sed 's/\.$//')
    
    if [[ -z "$cname" ]]; then
        echo -e "${GREEN}✓ No CNAME record found${NC}"
        echo -e "${BLUE}[i] This subdomain is not vulnerable to CNAME-based takeover${NC}"
    else
        echo -e "${CYAN}CNAME:${NC} $cname"
        
        # Check if CNAME resolves
        if ! host "$cname" >/dev/null 2>&1; then
            echo -e "${RED}⚠ WARNING: Dangling CNAME detected!${NC}"
            echo -e "${YELLOW}The CNAME record points to a non-existent host${NC}"
        fi
        
        # Check against fingerprints
        local vulnerable=false
        for service in "${!TAKEOVER_FINGERPRINTS[@]}"; do
            if echo "$cname" | grep -qi "$service"; then
                echo -e "\n${MAGENTA}Potential Service:${NC} $service"
                
                local response=$(curl -sL --max-time 5 "http://$check_subdomain" 2>/dev/null)
                local patterns="${TAKEOVER_FINGERPRINTS[$service]}"
                IFS='|' read -ra PATTERNS <<< "$patterns"
                
                for pattern in "${PATTERNS[@]}"; do
                    if echo "$response" | grep -qi "$pattern"; then
                        echo -e "${RED}${BOLD}⚠ VULNERABLE TO TAKEOVER!${NC}"
                        echo -e "${YELLOW}Evidence:${NC} $pattern"
                        vulnerable=true
                        break 2
                    fi
                done
            fi
        done
        
        if [[ "$vulnerable" == false ]]; then
            echo -e "${GREEN}✓ No takeover vulnerability detected${NC}"
        fi
    fi
    
    echo -ne "\n${YELLOW}Press Enter to continue...${NC}"
    read
}

# View scan history
view_scan_history() {
    clear
    show_banner
    echo -e "${CYAN}${BOLD}📊 Scan History${NC}\n"
    
    # Find all databases
    local dbs=$(find . -name "chaathan.db" 2>/dev/null)
    
    if [[ -z "$dbs" ]]; then
        echo -e "${YELLOW}No scan history found${NC}"
    else
        echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        for db in $dbs; do
            echo -e "\n${WHITE}Database:${NC} $db"
            sqlite3 "$db" "SELECT '  Domain: ' || domain || char(10) || '  Date: ' || scan_date || char(10) || '  Vulnerabilities: ' || vulnerable_count FROM scan_info ORDER BY scan_id DESC LIMIT 1;" 2>/dev/null
            echo ""
        done
        echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    fi
    
    echo -ne "\n${YELLOW}Press Enter to continue...${NC}"
    read
}

# Export menu
export_menu() {
    clear
    show_banner
    echo -e "${CYAN}${BOLD}📤 Export Results${NC}\n"
    
    if [[ ! -f "$VULNERABLE_FILE" ]]; then
        # Try to find most recent vulnerable file
        VULNERABLE_FILE=$(find . -name "vulnerabilities.txt" -type f 2>/dev/null | head -1)
    fi
    
    if [[ ! -f "$VULNERABLE_FILE" || ! -s "$VULNERABLE_FILE" ]]; then
        echo -e "${YELLOW}No data to export. Run a scan first.${NC}"
        echo -ne "\n${YELLOW}Press Enter to continue...${NC}"
        read
        return
    fi
    
    echo -e "  ${YELLOW}[1]${NC} Export to JSON"
    echo -e "  ${YELLOW}[2]${NC} Export to CSV"
    echo -e "  ${YELLOW}[3]${NC} Export to XML"
    echo -e "  ${YELLOW}[4]${NC} Back\n"
    
    echo -ne "${CYAN}Select format:${NC} "
    read -r export_choice
    
    local export_file=""
    local export_dir=$(dirname "$VULNERABLE_FILE")
    
    case $export_choice in
        1)
            export_file="$export_dir/vulnerabilities_$(date +%Y%m%d_%H%M%S).json"
            echo "{" > "$export_file"
            echo "  \"scan_date\": \"$(date '+%Y-%m-%d %H:%M:%S')\"," >> "$export_file"
            echo "  \"vulnerabilities\": [" >> "$export_file"
            
            local first=true
            while IFS='|' read -r sub cname svc type sev fing det; do
                [[ "$first" == false ]] && echo "," >> "$export_file"
                cat >> "$export_file" << JSONEOF
    {
      "subdomain": "$sub",
      "cname": "$cname",
      "service": "$svc",
      "type": "$type",
      "severity": "$sev",
      "fingerprint": "$fing"
    }
JSONEOF
                first=false
            done < "$VULNERABLE_FILE"
            echo -e "\n  ]\n}" >> "$export_file"
            ;;
        2)
            export_file="$export_dir/vulnerabilities_$(date +%Y%m%d_%H%M%S).csv"
            echo "Subdomain,CNAME,Service,Type,Severity,Fingerprint" > "$export_file"
            while IFS='|' read -r sub cname svc type sev fing det; do
                echo "\"$sub\",\"$cname\",\"$svc\",\"$type\",\"$sev\",\"$fing\"" >> "$export_file"
            done < "$VULNERABLE_FILE"
            ;;
        3)
            export_file="$export_dir/vulnerabilities_$(date +%Y%m%d_%H%M%S).xml"
            cat > "$export_file" << XMLEOF
<?xml version="1.0" encoding="UTF-8"?>
<chaathan_scan>
  <scan_info>
    <date>$(date '+%Y-%m-%d %H:%M:%S')</date>
  </scan_info>
  <vulnerabilities>
XMLEOF
            while IFS='|' read -r sub cname svc type sev fing det; do
                cat >> "$export_file" << XMLEOF
    <vulnerability>
      <subdomain>$sub</subdomain>
      <cname>$cname</cname>
      <service>$svc</service>
      <type>$type</type>
      <severity>$sev</severity>
      <fingerprint><![CDATA[$fing]]></fingerprint>
    </vulnerability>
XMLEOF
            done < "$VULNERABLE_FILE"
            echo "  </vulnerabilities>" >> "$export_file"
            echo "</chaathan_scan>" >> "$export_file"
            ;;
        *)
            return
            ;;
    esac
    
    if [[ ! -z "$export_file" ]]; then
        echo -e "\n${GREEN}✓ Export successful!${NC}"
        echo -e "${CYAN}File saved to: ${BOLD}$export_file${NC}"
    fi
    
    echo -ne "\n${YELLOW}Press Enter to continue...${NC}"
    read
}

# Show statistics
show_statistics() {
    clear
    show_banner
    echo -e "${CYAN}${BOLD}📊 Comprehensive Statistics${NC}\n"
    
    local dbs=$(find . -name "chaathan.db" 2>/dev/null)
    
    if [[ -z "$dbs" ]]; then
        echo -e "${YELLOW}No statistics available. Run a scan first.${NC}"
        echo -ne "\n${YELLOW}Press Enter to continue...${NC}"
        read
        return
    fi
    
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    for db in $dbs; do
        echo -e "\n${BOLD}Database: ${CYAN}$db${NC}"
        
        # Overall statistics
        sqlite3 "$db" "SELECT 
            '  Total Scans: ' || COUNT(*) || char(10) ||
            '  Total Subdomains: ' || COALESCE(SUM(total_subdomains), 0) || char(10) ||
            '  Active Subdomains: ' || COALESCE(SUM(active_subdomains), 0) || char(10) ||
            '  Vulnerabilities: ' || COALESCE(SUM(vulnerable_count), 0)
        FROM scan_info;" 2>/dev/null
        
        # Most vulnerable services
        echo -e "\n${BOLD}  Top Affected Services:${NC}"
        sqlite3 -header -column "$db" "SELECT 
            service as 'Service',
            COUNT(*) as 'Count'
        FROM vulnerabilities 
        GROUP BY service 
        ORDER BY COUNT(*) DESC 
        LIMIT 5;" 2>/dev/null | sed 's/^/    /'
    done
    
    echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    echo -ne "\n${YELLOW}Press Enter to continue...${NC}"
    read
}

# About
show_about() {
    clear
    show_banner
    echo -e "${CYAN}${BOLD}ℹ️  About CHAATHAN${NC}\n"
    
    cat << 'ABOUTEOF'
Version:          2.0
Author:           Advanced Security Research Team
License:          MIT
Description:      Next-generation subdomain takeover detection
                  framework with advanced enumeration capabilities

Key Features:
  ✓ Modern subdomain enumeration from 15+ sources
  ✓ 50+ cloud service takeover fingerprints
  ✓ Certificate Transparency monitoring
  ✓ Passive DNS intelligence gathering
  ✓ Active vulnerability verification
  ✓ Advanced DNS enumeration techniques
  ✓ Comprehensive PDF/HTML reporting
  ✓ SQLite database storage
  ✓ Multiple export formats (JSON, CSV, XML)
  ✓ Interactive CLI interface

Supported Services:
  • AWS (S3, CloudFront, Elastic Beanstalk)
  • Azure (App Service, CDN, API Management)
  • GitHub Pages, GitLab Pages, Bitbucket
  • Heroku, Netlify, Vercel, Render, Railway
  • Shopify, Zendesk, Intercom, WordPress
  • And 40+ more platforms...

Enumeration Sources:
  • crt.sh, CertSpotter, Facebook CT
  • HackerTarget, ThreatCrowd, AlienVault OTX
  • URLScan.io, RapidDNS, Anubis
  • BufferOver, DNS zone transfers
  • Subdomain bruteforce & permutations

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CHAATHAN - Advanced Offensive Security Testing Framework
For authorized security assessments only
ABOUTEOF
    
    echo -ne "\n${YELLOW}Press Enter to continue...${NC}"
    read
}

# Help function
show_help() {
    cat << 'HELPEOF'

   ██████╗██╗  ██╗ █████╗  █████╗ ████████╗██╗  ██╗ █████╗ ███╗   ██╗
  ██╔════╝██║  ██║██╔══██╗██╔══██╗╚══██╔══╝██║  ██║██╔══██╗████╗  ██║
  ██║     ███████║███████║███████║   ██║   ███████║███████║██╔██╗ ██║
  ██║     ██╔══██║██╔══██║██╔══██║   ██║   ██╔══██║██╔══██║██║╚██╗██║
  ╚██████╗██║  ██║██║  ██║██║  ██║   ██║   ██║  ██║██║  ██║██║ ╚████║
   ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝

Advanced Subdomain Takeover Detection Framework v2.0

USAGE:
    ./chaathan.sh [OPTIONS]

MODES:
    Interactive Mode:
        ./chaathan.sh                   # Launch interactive menu
    
    Command Line Mode:
        ./chaathan.sh -d <domain>       # Direct scan

OPTIONS:
    -d, --domain <domain>         Target domain (required for CLI)
    -o, --output <directory>      Output directory
                                  Default: ./chaathan_DOMAIN_TIMESTAMP
    -t, --timeout <seconds>       Connection timeout (default: 5)
    -T, --threads <number>        Concurrent checks (default: 15)
    --no-report                   Skip PDF report generation
    --no-db                       Skip database storage
    -v, --verbose                 Verbose output
    -q, --quiet                   Minimal output
    -h, --help                    Show this help
    --version                     Show version

EXAMPLES:
    # Interactive mode (recommended)
    ./chaathan.sh

    # Quick scan
    ./chaathan.sh -d example.com

    # Full scan with custom settings
    ./chaathan.sh -d target.com -o /tmp/results -T 20 -t 3

    # Quiet mode
    ./chaathan.sh -d example.com -q --no-report

ENUMERATION SOURCES:
    • Certificate Transparency (crt.sh, CertSpotter)
    • Passive DNS (HackerTarget, ThreatCrowd, AlienVault)
    • Web Archives (URLScan.io, RapidDNS, Anubis)
    • DNS Databases (BufferOver, Zone Transfers)
    • Active Bruteforce & Permutation Generation

DETECTION CAPABILITIES:
    [CRITICAL]  AWS S3 bucket takeover
    [CRITICAL]  Azure App Service takeover
    [CRITICAL]  GitHub Pages takeover
    [CRITICAL]  Heroku app takeover
    [HIGH]      Dangling CNAME records
    [HIGH]      Netlify/Vercel/Shopify vulnerabilities
    [MEDIUM]    Generic service misconfigurations

OUTPUT FILES:
    • chaathan.db                   SQLite database
    • chaathan_report_*.pdf         Professional PDF report
    • all_subdomains.txt            Complete subdomain list
    • active_subdomains.txt         Active subdomains only
    • vulnerabilities.txt           Vulnerability details

REQUIREMENTS:
    • bash 4.0+
    • curl
    • dig (dnsutils)
    • host
    • sqlite3
    • grep, awk, sed
    • wkhtmltopdf (optional, for PDF reports)

INSTALLATION:
    # Make executable
    chmod +x chaathan.sh
    
    # Install dependencies (Debian/Ubuntu)
    sudo apt-get install curl dnsutils sqlite3 wkhtmltopdf

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CHAATHAN - Advanced Offensive Security Testing Framework
Only use for authorized security assessments

HELPEOF
}

# Check dependencies
check_dependencies() {
    local missing_deps=()
    local optional_deps=()
    
    command -v curl &> /dev/null || missing_deps+=("curl")
    command -v dig &> /dev/null || missing_deps+=("dig/dnsutils")
    command -v sqlite3 &> /dev/null || missing_deps+=("sqlite3")
    command -v host &> /dev/null || missing_deps+=("host")
    command -v wkhtmltopdf &> /dev/null || optional_deps+=("wkhtmltopdf")
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        echo -e "${RED}${BOLD}[!] Missing required dependencies:${NC}"
        for dep in "${missing_deps[@]}"; do
            echo -e "    ${YELLOW}•${NC} $dep"
        done
        echo -e "\n${YELLOW}Install with:${NC}"
        echo -e "  ${CYAN}sudo apt-get install curl dnsutils sqlite3${NC}"
        echo -e "  ${CYAN}or${NC}"
        echo -e "  ${CYAN}sudo yum install bind-utils sqlite${NC}\n"
        exit 1
    fi
    
    if [[ ${#optional_deps[@]} -gt 0 ]]; then
        echo -e "${YELLOW}[!] Optional dependencies not found:${NC}"
        for dep in "${optional_deps[@]}"; do
            echo -e "    ${DIM}•${NC} $dep ${DIM}(PDF reports will be in HTML format)${NC}"
        done
        echo ""
    fi
}

# Main function
main() {
    # Check if running as root (not recommended)
    if [[ $EUID -eq 0 ]]; then
        echo -e "${YELLOW}[!] Warning: Running as root is not recommended${NC}\n"
    fi
    
    # Interactive mode if no arguments
    if [[ $# -eq 0 ]]; then
        show_interactive_menu
        exit 0
    fi
    
    show_banner
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -d|--domain)
                TARGET_DOMAIN="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -t|--timeout)
                TIMEOUT="$2"
                shift 2
                ;;
            -T|--threads)
                THREADS="$2"
                shift 2
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            --version)
                echo -e "${CYAN}${BOLD}CHAATHAN v2.0${NC}"
                echo -e "${DIM}Advanced Subdomain Takeover Detection Framework${NC}"
                exit 0
                ;;
            -v|--verbose)
                set -x
                shift
                ;;
            -q|--quiet)
                exec 1>/dev/null 2>&1
                shift
                ;;
            --no-report)
                SKIP_REPORT=true
                shift
                ;;
            --no-db)
                SKIP_DB=true
                shift
                ;;
            *)
                echo -e "${RED}[!] Unknown option: $1${NC}"
                echo -e "${YELLOW}[*] Use -h or --help for usage information${NC}\n"
                exit 1
                ;;
        esac
    done
    
    # Validate input
    if [[ -z "$TARGET_DOMAIN" ]]; then
        echo -e "${RED}[!] Error: Target domain is required${NC}"
        echo -e "${YELLOW}[*] Usage: $0 -d example.com${NC}"
        echo -e "${YELLOW}[*] Or run without arguments for interactive mode${NC}\n"
        exit 1
    fi
    
    # Validate domain format
   # Validate domain format
if ! echo "$TARGET_DOMAIN" | grep -qE '^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'; then
    echo -e "${RED}[!] Error: Invalid domain format${NC}\n"
    exit 1
fi
    
    # Set default output directory
    if [[ -z "$OUTPUT_DIR" ]]; then
        OUTPUT_DIR="./chaathan_${TARGET_DOMAIN}_$(date +%Y%m%d_%H%M%S)"
    fi
    
    mkdir -p "$OUTPUT_DIR"
    DB_FILE="$OUTPUT_DIR/chaathan.db"
    
    # Initialize database
    if [[ "$SKIP_DB" != true ]]; then
        init_database
    fi
    
    # Perform scan
    perform_scan
    
    # Save to database
    if [[ "$SKIP_DB" != true ]]; then
        save_to_database
    fi
    
    # Generate report
    if [[ "$SKIP_REPORT" != true ]]; then
        REPORT_FILE=$(generate_pdf_report)
    fi
    
    # Display results
    display_results
    
    # Cleanup
    cleanup
    
    echo -e "${GREEN}${BOLD}[✓] Scan completed successfully!${NC}"
    echo -e "${CYAN}[i] Results saved to: ${BOLD}$OUTPUT_DIR${NC}\n"
}

# Trap cleanup on exit
trap cleanup EXIT INT TERM

# Check dependencies before running
check_dependencies

# Run main function
main "$@"