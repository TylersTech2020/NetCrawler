# NetCrawler
Router Vulnerability scan w/ NMAP, RouterSploit, and Metasploit


### Approach
1. **Basic Scanning**:
   - Ping sweep to find live hosts.
   - Port scan for common router ports (22, 23, 80, 443, 8080).
   - Banner grabbing to identify services.
   - Basic default credential check for HTTP/HTTPS.
2. **Nmap Integration**:
   - Purpose: Advanced port scanning, service detection, and vulnerability scanning via scripts (e.g., `vulners.nse`).
   - Use: Identify open ports, services, and potential CVEs.
3. **RouterSploit Integration**:
   - Purpose: Router-specific vulnerability scanning and exploitation.
   - Use: Run the `autopwn` scanner and HTTP credential check.
4. **Metasploit Integration**:
   - Purpose: Broad penetration testing for network devices.
   - Use: Scan ports, detect HTTP versions, and attempt HTTP login brute-forcing.
5. **Requirements**: Linux/Unix system, Bash, and the tools installed.

### Prerequisites
- **Nmap**: Install via package manager (e.g., `sudo apt install nmap` on Ubuntu, `sudo yum install nmap` on CentOS).
- **RouterSploit**:
  - Install Python 3: `sudo apt install python3 python3-pip` (or equivalent).
  - Install Git: `sudo apt install git`.
  - Clone RouterSploit: `git clone https://github.com/threat9/routersploit.git`
  - Navigate: `cd routersploit`
  - Install dependencies: `pip3 install -r requirements.txt`
- **Metasploit**:
  - Install Metasploit Framework: Download from [metasploit.com](https://www.metasploit.com/download) or use a package manager (e.g., `sudo apt install metasploit-framework` on some distros).
  - Initialize database: `msfdb init` (if needed).
- **Permissions**: Written consent from the network/device owner.
- **Tools**: Ensure `curl` is installed for banner grabbing and credential tests (e.g., `sudo apt install curl`).

### Bash Script

```bash
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
```

### How It Works
1. **Ping Sweep**: Uses `ping` to find live hosts in the range (e.g., 192.168.1.1 to 192.168.1.254).
2. **Port Scan**: A fallback scan uses Bash’s `/dev/tcp` to check common router ports (22, 23, 80, 443, 8080).
3. **Banner Grabbing**: Uses `curl` for HTTP/HTTPS banners and `nc` (netcat) for SSH/Telnet to identify services.
4. **Default Credentials**: Tests HTTP/HTTPS for common credentials (e.g., admin:admin) using `curl`.
5. **Nmap Integration**:
   - Runs a service version scan (`-sV -p 22,23,80,443,8080`) to detect software.
   - Uses `vulners.nse` to check for known vulnerabilities.
6. **RouterSploit Integration**:
   - Runs the `scanners/autopwn` module for general router vulnerability scanning.
   - Uses `creds/generic/http_default_creds` to test HTTP credentials.
7. **Metasploit Integration**:
   - Creates a resource script to:
     - Scan ports (`auxiliary/scanner/portscan/tcp`).
     - Detect HTTP versions (`auxiliary/scanner/http/http_version`).
     - Attempt HTTP login brute-forcing (`auxiliary/scanner/http/http_login`).
   - Executes via `msfconsole` and logs results.
8. **Output**: Results (ping, ports, banners, credentials, Nmap, RouterSploit, Metasploit) are saved to `RouterScanResults.txt`.

### How to Use
1. **Setup**:
   - Install Nmap, RouterSploit, Metasploit, and `curl` (see prerequisites).
   - Update variables:
     - `NETWORK`: Set to your subnet (e.g., "10.0.0").
     - `RANGE`: Adjust range (e.g., "1-10" for a smaller test).
     - `ROUTERSPLOIT_PATH`: Path to RouterSploit directory (e.g., `/home/user/routersploit`).
     - `MSF_PATH`: Path to `msfconsole` (e.g., `/opt/metasploit-framework/bin/msfconsole`).
     - For Metasploit’s `http_login`, update `/path/to/wordlist.txt` to a user/password wordlist (e.g., from SecLists on GitHub or create your own).
2. **Run**:
   - Save the script as `router_vuln_scan.sh`.
   - Make executable: `chmod +x router_vuln_scan.sh`
   - Execute: `./router_vuln_scan.sh`
3. **Review**: Check `RouterScanResults.txt` for results.

### Limitations
- **Dependencies**: Requires Nmap, RouterSploit, Metasploit, and `curl` installed.
- **Wordlist**: Metasploit’s `http_login` needs a user/password wordlist; provide one.
- **Performance**: Scanning with multiple tools can be slow; narrow the range for testing.
- **Depth**: Basic modules are used; advanced exploits need manual tuning.
- **Detection**: Firewalls/IDS may flag scans or exploit attempts.

### Further Enhancements
- **RouterSploit**: Add specific modules (e.g., `exploits/routers/dlink/dns_hijack`) for targeted brands.
- **Metasploit**: Include exploit modules (e.g., `exploit/multi/http/dlink_dir_615h1_auth_bypass`).
- **Error Handling**: Improve for timeouts or tool failures.

ToDo:
- Add specific RouterSploit or Metasploit modules for a router brand (e.g., D-Link)?
- Provide a sample wordlist or detailed setup instructions?
- Optimize for speed or specific vulnerabilities?
