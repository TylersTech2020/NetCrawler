#!/bin/bash

# Network Scan for Router Vulnerabilities with Nmap, RouterSploit, and Metasploit
# Usage: Modify NETWORK, RANGE, ROUTERSPLOIT_PATH, and MSF_PATH to match your setup
# Requires: Nmap, RouterSploit, Metasploit, curl installed, and permission to scan

# Define network and paths
NETWORK="192.168.1" # Change to your network (e.g., "10.0.0" for 10.0.0.x)
RANGE="1-254" # IP range to scan
PORTS="22,23,80,443,8080" # Common router ports: SSH, Telnet, HTTP, HTTPS, alt HTTP
NMAP_PATH=$(which nmap) # Nmap binary path
ROUTERSPLOIT_PATH="/path/to/routersploit" # Adjust to your RouterSploit directory
MSF_PATH="/opt/metasploit-framework/bin/msfconsole" # Adjust to your Metasploit msfconsole path
OUTPUT_FILE="RouterScanResults.txt"

# Initialize output file
echo "Network Scan Results - $(date)" > "$OUTPUT_FILE"

# Function to test if host is alive (ping)
test_host_alive() {
    local ip=$1
    if ping -c 1 -W 1 "$ip" > /dev/null 2>&1; then
        echo "true"
    else
        echo "false"
    fi
}

# Function to scan ports (fallback using netcat or timeout)
scan_ports() {
    local ip=$1
    local ports=$2
    local open_ports=""
    for port in $(echo "$ports" | tr ',' ' '); do
        if timeout 1 bash -c "echo > /dev/tcp/$ip/$port" 2> /dev/null; then
            open_ports="$open_ports $port"
        fi
    done
    echo "$open_ports"
}

# Function for banner grabbing (basic HTTP/SSH check)
get_banner() {
    local ip=$1
    local port=$2
    if [ "$port" -eq 80 ] || [ "$port" -eq 8080 ] || [ "$port" -eq 443 ]; then
        local proto="http"
        [ "$port" -eq 443 ] && proto="https"
        banner=$(curl -s -m 5 --head "$proto://$ip" | grep -i "server:" || echo "No HTTP Banner")
        echo "HTTP Banner (Port $port): $banner"
    elif [ "$port" -eq 22 ] || [ "$port" -eq 23 ]; then
        banner=$(timeout 5 nc -v -w 1 "$ip" "$port" 2>&1 | head -n 1 || echo "No Banner")
        echo "Service Banner (Port $port): $banner"
    else
        echo "No Banner (Port $port)"
    fi
}

# Function to test default credentials (basic HTTP example)
test_default_credentials() {
    local ip=$1
    local port=$2
    local proto="http"
    [ "$port" -eq 443 ] && proto="https"
    local credentials=("admin:admin" "admin:password" "root:root")
    for cred in "${credentials[@]}"; do
        user=$(echo "$cred" | cut -d':' -f1)
        pass=$(echo "$cred" | cut -d':' -f2)
        response=$(curl -s -m 5 --user "$user:$pass" "$proto://$ip" -o /dev/null -w "%{http_code}")
        if [ "$response" = "200" ]; then
            echo "VULNERABILITY: Default credentials worked! User: $user Pass: $pass"
            return
        fi
    done
    echo "No default credentials found."
}

# Function to run Nmap scan
run_nmap_scan() {
    local ip=$1
    if [ ! -x "$NMAP_PATH" ]; then
        echo "ERROR: Nmap not found at $NMAP_PATH. Install Nmap and update path." | tee -a "$OUTPUT_FILE"
        return
    fi
    echo "Nmap Scan for $ip :" >> "$OUTPUT_FILE"
    # Basic Nmap scan: port scan and service version detection
    nmap -sV -p "$PORTS" "$ip" >> "$OUTPUT_FILE" 2>&1 || echo "ERROR: Nmap scan failed for $ip" >> "$OUTPUT_FILE"
    echo "Nmap Vulnerability Scan for $ip :" >> "$OUTPUT_FILE"
    # Vulnerability scan with vulners.nse script
    nmap -sV --script vulners.nse "$ip" >> "$OUTPUT_FILE" 2>&1 || echo "ERROR: Nmap vuln scan failed for $ip" >> "$OUTPUT_FILE"
}

# Function to run RouterSploit scan
run_routersploit_scan() {
    local ip=$1
    if [ ! -d "$ROUTERSPLOIT_PATH" ]; then
        echo "ERROR: RouterSploit not found at $ROUTERSPLOIT_PATH. Install RouterSploit and update path." | tee -a "$OUTPUT_FILE"
        return
    fi
    cd "$ROUTERSPLOIT_PATH" || return
    echo "RouterSploit Scan for $ip :" >> "$OUTPUT_FILE"
    # Run autopwn scanner and basic credential check
    python3 rsf.py -c "use scanners/autopwn; set target $ip; run; use creds/generic/http_default_creds; set target $ip; run; exit" >> "$OUTPUT_FILE" 2>&1 || \
        echo "ERROR: RouterSploit scan failed for $ip" >> "$OUTPUT_FILE"
    cd - > /dev/null
}

# Function to run Metasploit scan
run_metasploit_scan() {
    local ip=$1
    if [ ! -x "$MSF_PATH" ]; then
        echo "ERROR: Metasploit not found at $MSF_PATH. Install Metasploit and update path." | tee -a "$OUTPUT_FILE"
        return
    fi
    # Create a temporary Metasploit resource script
    msf_script="msf_temp_$$.rc"
    cat << EOF > "$msf_script"
use auxiliary/scanner/portscan/tcp
set RHOSTS $ip
set PORTS $PORTS
run
use auxiliary/scanner/http/http_version
set RHOSTS $ip
run
use auxiliary/scanner/http/http_login
set RHOSTS $ip
set USERPASS_FILE /path/to/wordlist.txt
set STOP_ON_SUCCESS true
run
exit
EOF
    echo "Metasploit Scan for $ip :" >> "$OUTPUT_FILE"
    # Run Metasploit with the resource script
    $MSF_PATH -q -r "$msf_script" >> "$OUTPUT_FILE" 2>&1 || echo "ERROR: Metasploit scan failed for $ip" >> "$OUTPUT_FILE"
    # Clean up temporary script
    rm -f "$msf_script"
}

# Main scan loop
echo "Starting network scan for $NETWORK.x..."
for i in $(seq $(echo $RANGE | cut -d'-' -f1) $(echo $RANGE | cut -d'-' -f2)); do
    ip="$NETWORK.$i"
    echo "Pinging $ip..."
    if [ "$(test_host_alive $ip)" = "true" ]; then
        echo "Host $ip is alive" >> "$OUTPUT_FILE"
        open_ports=$(scan_ports "$ip" "$PORTS")
        if [ -n "$open_ports" ]; then
            echo "Open ports on $ip : $open_ports" >> "$OUTPUT_FILE"
            for port in $open_ports; do
                get_banner "$ip" "$port" >> "$OUTPUT_FILE"
                if [ "$port" -eq 80 ] || [ "$port" -eq 443 ] || [ "$port" -eq 8080 ]; then
                    test_default_credentials "$ip" "$port" >> "$OUTPUT_FILE"
                fi
            done
            # Run Nmap scan
            run_nmap_scan "$ip"
            # Run RouterSploit scan
            run_routersploit_scan "$ip"
            # Run Metasploit scan
            run_metasploit_scan "$ip"
        else
            echo "No open ports detected on $ip" >> "$OUTPUT_FILE"
        fi
    else
        echo "Host $ip is down" >> "$OUTPUT_FILE"
    fi
done

echo "Scan complete. Results saved to $OUTPUT_FILE"
echo "Scan completed at $(date)" >> "$OUTPUT_FILE"
