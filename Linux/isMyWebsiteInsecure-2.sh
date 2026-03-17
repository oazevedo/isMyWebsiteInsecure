#!/bin/bash
# isMyWebsiteInsecure-2.sh
# developed by Oscar Azevedo, oscar.azevedo@aeportugal.pt, oscar.msazevedo@gmail.com
# check the security of a given website with public command line tools
#
# v1.5, modified on 2026-03-01
#  - added rotate_ip using Proton VPN
#  - added evasion capability
#
# v1.6, modified on 2026-03-03
#  - wpscan only runs if WordPress is detected by whatweb
#  - joomscan only runs if Joomla is detected by whatweb
#
# v1.7, modified on 2026-03-14
#  - joomscan, removed
#  - added sudo before nmap, ex. sudo nmap ...
#  - updated script to run latest Nikto version 2.6.0 https://github.com/sullo/nikto/releases
#  


# ──── Evasion User-Agent ──────────────────────────────────────────────────────
USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"


# ──── WAF Bypass Headers (used by curl, nikto, nuclei, dalfox) ───────────────
# Spoofing X-Forwarded-For / X-Real-IP tricks many WAFs into treating the
# request as coming from localhost (a trusted internal IP).
# Accept-Language / Accept-Encoding / Referer mimic legitimate browser traffic
# to avoid anomaly-score triggers on WAFs that check header completeness.
WAF_BYPASS_HEADERS=(
    -H "X-Forwarded-For: 127.0.0.1"
    -H "X-Real-IP: 127.0.0.1"
    -H "X-Originating-IP: 127.0.0.1"
    -H "X-Remote-IP: 127.0.0.1"
    -H "X-Remote-Addr: 127.0.0.1"
    -H "Accept-Language: en-US,en;q=0.9"
    -H "Accept-Encoding: gzip, deflate, br"
    -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    -H "Referer: https://www.google.com/"
    -H "Cache-Control: no-cache"
    -H "Pragma: no-cache"
)


# ──── Helper: print then execute a command ────────────────────────────────────
# Usage: run_cmd cmd arg1 arg2 ...
run_cmd() {
	echo -e "\e[1;32m $* \e[0m" >&2
    "$@"
}


# ──── Validate URL and extract host, domain, port, ipv4 ─────────────────────
# Validates:
#   - scheme        : http:// or https://
#   - host          : hostname, subdomain, or bare IPv4 (no IPv6 brackets)
#   - optional port : :1–65535
#   - optional path : any printable non-space characters
# On success, sets globals: host  domain  port  ipv4
validate_url() {
    local url="$1"

    # Must start with http:// or https://
    if [[ ! "$url" =~ ^https?:// ]]; then
        echo "Error: URL must start with http:// or https://"
        exit 1
    fi

    # Strip scheme to isolate the rest
    local rest="${url#http://}"
    rest="${rest#https://}"

    # Must have a non-empty host (no spaces, no bare slash at position 0)
    if [[ -z "$rest" || "$rest" == /* ]]; then
        echo "Error: URL is missing a hostname."
        exit 1
    fi

    # Split host+port from path (everything before the first /)
    local hostport="${rest%%/*}"
    if [[ -z "$hostport" ]]; then
        echo "Error: URL is missing a hostname."
        exit 1
    fi

    # ── Extract and validate optional port ───────────────────────────────────
    if [[ "$hostport" =~ :([0-9]+)$ ]]; then
        port="${BASH_REMATCH[1]}"
        if (( port < 1 || port > 65535 )); then
            echo "Error: Port number '$port' is out of the valid range (1–65535)."
            exit 1
        fi
        hostport="${hostport%:$port}"   # strip port to validate host alone
    else
        port=""
    fi

    # ── Validate and set host ─────────────────────────────────────────────────
    local ipv4_re='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
    local host_re='^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'

    if [[ "$hostport" =~ $ipv4_re ]]; then
        IFS='.' read -r o1 o2 o3 o4 <<< "$hostport"
        for octet in "$o1" "$o2" "$o3" "$o4"; do
            if (( octet > 255 )); then
                echo "Error: '$hostport' is not a valid IPv4 address."
                exit 1
            fi
        done
    elif [[ ! "$hostport" =~ $host_re ]]; then
        echo "Error: '$hostport' is not a valid hostname."
        echo "       Expected format: https://example.com or https://sub.domain.org:8443/path"
        exit 1
    fi
    host="$hostport"

    # ── Extract registered domain (last two labels) ───────────────────────────
    domain=$(awk -F. '{n=NF; if(n>=2) print $(n-1)"."$n; else print $0}' <<< "$host")
    if [[ -z "$domain" ]]; then
        echo "Error: Could not extract a registered domain from host '$host'."
        exit 1
    fi

    # ── Resolve IPv4 — filter out CNAME lines, take first A record ───────────
    ipv4=$(dig +short "$host" A | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -n1)
    if [[ -z "$ipv4" ]]; then
        echo "Error: Could not resolve an IPv4 address for '$host'. Check that the host exists and DNS is reachable."
        exit 1
    fi
}


# ──── Function to check if required tools are installed ──────────────────────
check_tools() {
    required_tools=(whois dnsrecon whatweb wpscan sqlmap curl nmap sslscan nrich dig dalfox nuclei nikto)
    missing=()
    for tool in "${required_tools[@]}"; do
        command -v "$tool" &> /dev/null || missing+=("$tool")
    done
    if [ "${#missing[@]}" -gt 0 ]; then
        echo "Missing tools: ${missing[*]}"
        exit 1
    fi
}


# ──── Function to rotate VPN public IP Address ────────────────────────────────
vpn_rotate_ip() {
    if [[ "$VPN" != "true" ]]; then
        return 0
    fi

    if [[ "$1" == "no" ]]; then
        echo -e "\e[34m[*] ProtonVPN — disconnecting...\e[0m"
        protonvpn disconnect
        return 0
    fi

    echo -e "\e[34m[*] ProtonVPN — switching to a new random server...\e[0m"
    protonvpn disconnect && protonvpn connect --random
}


# ──── function to random timout between 15 and 120 seconds ───────────────────────
random_timeout() {
    local seconds=$(( RANDOM % 105 + 15 ))
    echo -e "waiting $seconds seconds"
    for (( i=seconds; i>0; i-- )); do
        printf "\r⏳ remaining: %3d seconds" "$i"
        sleep 1
    done
    printf "\r✅ Done!                    \n"
}


# Main script
main() {

    # Check if a URL parameter is provided
    if [ "$#" -ne 1 ]; then
        echo -e "Usage: $0 <url>"
        exit 1
    fi

    # Validate the URL format
    url="$1"
    validate_url "$url"


    # Check if required tools are installed
    check_tools


    # Display VPN recommendation
    echo -e "\n\e[33m💡 VPN Tip: Using a VPN with IP rotation is recommended as a WAF evasion technique,"
    echo -e "   but this script runs fully without one — VPN is optional."
    echo -e "   When ProtonVPN is installed, the script detects it and rotates the IP automatically between scans."
    echo -e "   Any other VPN with CLI support and random server switching can be used instead of ProtonVPN.\e[0m\n"
	
	
	# Display ethical use warning
    echo -e "\e[1;33m⚠️  Warning: Ensure you have explicit authorization before running these tests."
    echo -e "             Unauthorized testing is illegal and unethical.\e[0m\n"

    # Ask user if they want to continue
    read -p "Do you want to continue running the script? (yes/no): " choice
    if [[ "$choice" != "yes" ]]; then
        echo "Exiting script."
        exit 0
    fi


    # Start Date
    start_ts=$(date +%s)
    echo -e "\n\nStart date: $(date +"%Y-%m-%d %H:%M") \n\n"
		

    # host, domain, port and ipv4 were all set by validate_url above
    echo "Host=$host"
    echo "Domain=$domain"
    echo "Port=${port:-(default)}"
    echo "IPv4=${ipv4:-(unresolved)}"
    echo "Url=$url"
    echo -e "\n"


    # ProtonVPN is installed?
    VPN="false"
    if command -v protonvpn &> /dev/null; then
        VPN="true"
        echo "ProtonVPN is installed."
        echo -e "\n"
    fi


    # ──── Let's go to Work! ───────────────────────────────────────────────────

    # sudo -v , update user's timestamp
	# to run every two and half hours:
	#  sudo visudo
	#    Defaults timestamp_timeout=150
    echo -e "[+] Running sudo update timestamp.. "
    run_cmd sudo -v
    echo -e "\n\n"
    
	
	vpn_rotate_ip
    random_timeout
    # WHOIS lookup for domain information
    # No evasion available — query goes to registry server, not the target
    echo -e "[+] Running WHOIS lookup..."
    run_cmd whois "$domain"
    echo -e "\n\n"


    vpn_rotate_ip
    random_timeout
    # DNSRecon - DNS reconnaissance
    # Using Google and Cloudflare public's DNS (8.8.8.8 and 1.1.1.1) to avoid querying target's nameserver directly
    echo -e "[+] Running DNS reconnaissance..."
    run_cmd dnsrecon --domain "$domain" \
                     --name_server 8.8.8.8,1.1.1.1
    echo -e "\n\n"

    
    vpn_rotate_ip
    random_timeout
    # SSLScan - SSL/TLS scan
    # No evasion available — TLS handshake is inherently identifiable
    echo -e "[+] Running SSL/TLS scan..."
    run_cmd sslscan "$host"
    echo -e "\n\n"

    
    vpn_rotate_ip
    random_timeout
    # CURL - get HTTP Headers
    # Random User-Agent to blend in with normal browser traffic
    echo -e "[+] Getting HTTP Headers..."
    run_cmd curl "$url" \
                 --head \
                 --user-agent "$USER_AGENT"
    echo -e "\n\n"


    vpn_rotate_ip
    random_timeout
    # Shodan Search Engine (nrich)
    # Passive lookup — no direct contact with target, no evasion needed
    echo -e "[+] Running Shodan scan..."
    run_cmd bash -c "echo \"$ipv4\" | nrich -"
    echo -e "\n\n"


    vpn_rotate_ip
    random_timeout
    # WhatWeb - Identify technologies used on the website
    # --aggression 1 = stealthy mode (single request, passive fingerprinting)
    echo -e "[+] Identifying technologies used on the website..."
	whatweb_output=$(run_cmd whatweb --aggression 1 \
	                                 --user-agent "$USER_AGENT" \
									 "$url")
    echo -e "$whatweb_output"
	echo -e "\n\n"


    # WPScan - Wordpress vulnerability scan (only if WordPress detected by whatweb)
    # --stealthy enables passive mode (no aggressive probing)
    echo -e "[+] Checking for WordPress..."
    if echo "$whatweb_output" | grep -qi "wordpress"; then
        vpn_rotate_ip
        random_timeout
        echo -e "[!] WordPress detected — running wpscan..."
        run_cmd wpscan --url "$url" \
                       --update \
                       --no-banner \
                       --stealthy
    else
        echo -e "[-] WordPress not detected — skipping wpscan."
    fi
    echo -e "\n\n"


    vpn_rotate_ip
    random_timeout
    # Host header injection test
    # Random User-Agent added to blend in with normal browser traffic
    echo -e "[+] Running Host header injection test..."
    host_header_injection_status=$(run_cmd curl -s \
	                                            -o /dev/null \
												-w "%{http_code}" \
                                                -A "$USER_AGENT" \
                                                -H "Host: malicious.example.com" "$url")
    echo -e "Host header injection test, HTTP code: $host_header_injection_status"
    if [ "$host_header_injection_status" -eq 200 ]; then
        echo -e " Vulnerable."
    fi
    echo -e "\n\n"


    if echo "$whatweb_output" | grep -qi "wordpress"; then
      vpn_rotate_ip
      random_timeout
      # XML RPC detect
      # Random User-Agent added to blend in with normal browser traffic
      echo -e "[+] XML RPC file detection..."
      xmlrpc_status=$(run_cmd curl -s \
	                               -o /dev/null \
								   -w "%{http_code}" \
                                   -A "$USER_AGENT" \
								   "${WAF_BYPASS_HEADERS[@]}" \
                                   --max-time 20 \
								   "$url/xmlrpc.php")
      echo -e "$url/xmlrpc.php detection, HTTP code: $xmlrpc_status"
      if [ "$xmlrpc_status" -eq 200 ]; then
	    echo -e " Vulnerable."
	  fi
      echo -e "\n\n"
	fi



    if echo "$whatweb_output" | grep -qi "wordpress"; then
      vpn_rotate_ip
      random_timeout
      # Readme.html detect
      # Random User-Agent added to blend in with normal browser traffic
      echo -e "[+] Readme file detection..."
      readme_status=$(run_cmd curl -s \
	                               -o /dev/null \
								   -w "%{http_code}" \
                                   -A "$USER_AGENT" \
								   "${WAF_BYPASS_HEADERS[@]}" \
                                   --max-time 20 \
								   "$url/readme.html")
      echo -e "$url/readme.html detection, HTTP code: $readme_status"
      if [ "$readme_status" -eq 200 ]; then
	    echo -e "Vulnerable."
	  fi
      echo -e "\n\n"
	fi
	
	
	vpn_rotate_ip
    random_timeout
    # Dalfox XSS Scanner
    # --waf-evasion enable WAF evasion by adjusting speed when detecting WAF (worker=1, delay=3s)  
    echo -e "[+] Dalfox xss scan..."
    run_cmd dalfox url "$url" \
                   --waf-evasion \
                   "${WAF_BYPASS_HEADERS[@]}"
    echo -e "\n\n"


    vpn_rotate_ip
    random_timeout
    # Nuclei vulnerabilities scan
    # timeout 2700, kill nuclei after 2700 seconds	
    # -rate-limit 10 slows requests to avoid triggering rate-based WAF rules, (default 150)
    # -concurrency 10 slows requests templates to be executed in parallel (default 25)
    # -timeout 15 -retries 3 -no-mhe, 15s before timeout, 3 retries and don't skip unresponsive hosts
    echo -e "[+] Nuclei vulnerabilities scan..."
    run_cmd timeout 2700 \
	        sudo \
            nuclei -u "$url" \
                   -rate-limit 10 \
                   -concurrency 10 \
                   -timeout 15 \
                   -retries 3 \
                   -no-mhe \
                   -H "User-Agent: $USER_AGENT" \
                   "${WAF_BYPASS_HEADERS[@]}"
    echo -e "\n\n"
	
	
	vpn_rotate_ip
    random_timeout
    # Nikto vulnerabilities scan
    # -maxtime 1800: 30 minutes	to run scan, after abort
    # -evasion 1234678 applies all available evasion techniques:
    #   1=random URI encoding, 2=directory self-reference (/./),
    #   3=premature URL ending (%00), 4=prepend long random string,
    #   6=TAB as request spacer, 7=random case sensitivity,
    #   8=Windows path separator (\)
	#  Nikto v2.6.0 - default: Randomized User-Agent selection per request
    echo -e "[+] Nikto vulnerabilities scan..."
    run_cmd nikto -h "$url" \
                  -maxtime 1800 \
                  -evasion 1234678 
    echo -e "\n\n"

	
    vpn_rotate_ip
    random_timeout
    # SQLmap check for SQL injection
    # --random-agent: rotates User-Agent to avoid UA-based blocking
    # --delay=3: 3s between requests to evade rate-based WAF rules
    # --level=3 --risk=2: broader coverage without overly destructive payloads
    # --hpp: HTTP parameter pollution to confuse WAF parameter parsing
    # --hex: encodes payloads in hex to bypass keyword-based WAF signatures
    # --tamper chain (layered obfuscation — order matters):
    #   space2comment   → replaces spaces with /**/ to break keyword+space patterns
    #   between         → rewrites AND/OR comparisons to evade boolean-logic rules
    #   randomcase      → randomizes SQL keyword casing (SeLeCt, UnIoN, etc.)
    #   charunicodeencode → Unicode-encodes characters (%u0053%u0045...)
    #   charencode      → URL-encodes characters (%53%45...)
    #   equaltolike     → replaces = with LIKE to evade equality-check signatures
    #   multiplespaces  → inserts multiple spaces between keywords
    #   percentage      → adds % between characters to break simple regex rules
    #   unmagicquotes   → escapes quotes with backslash to bypass quote filters
    echo -e "[+] SQLmap check for SQL injection"
    run_cmd timeout 2700 \
	        sqlmap -u "$url" \
                   --batch \
                   --random-agent \
                   --delay=3 \
                   --level=3 \
                   --risk=2 \
                   --hpp \
                   --hex \
                   --tamper=space2comment,between,randomcase,charunicodeencode,charencode,equaltolike,multiplespaces,percentage,unmagicquotes
    echo -e "\n\n"


    vpn_rotate_ip no
    random_timeout
    # Nmap vulnerabilities scan
    #  note: Nmap gives incorrect results with VPN enabled	
    echo -e "[+] Nmap vulnerabilities scan..."
    run_cmd timeout 600 \
	        sudo \
            nmap "$host" \
                 -sS \
				 -Pn \
				 -n \
				 --source-port 53 \
				 -D RND:10 \
                 --script vuln 
    echo -e "\n\n"  


    # End Date
    end_ts=$(date +%s)
    elapsed=$(( end_ts - start_ts ))
    hours=$(( elapsed / 3600 ))
    minutes=$(( (elapsed % 3600) / 60 ))
    seconds=$(( elapsed % 60 ))
    echo -e "End date: $(date +"%Y-%m-%d %H:%M") \n\n"
    echo -e "Total time: ${hours}h ${minutes}m ${seconds}s\n\n"
}

# Execute main function
main "$@"
