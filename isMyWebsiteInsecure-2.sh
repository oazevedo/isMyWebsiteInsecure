#!/bin/bash
# isMyWebsiteInsecure-2.sh
# developed by Oscar Azevedo, oscar.azevedo@aeportugal.pt, oscar.msazevedo@gmail.com
# check the security of a given website with public command line tools
#
# nmap: don't use with vpn because returns wrong results
#
# v1.5, modified on 2026-03-01
#  - added rotate_ip using Proton VPN
#  - added evasion capability
#
# v1.6, modified on 2026-03-03
#  - wpscan only runs if WordPress is detected by whatweb
#  - joomscan only runs if Joomla is detected by whatweb
#
# v1.7, modified on 2026-03-03
#  - replaced manual echo+command pairs with run_cmd helper
#  - removed ANSI color codes from all echo commands


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
# Prints the command in green, then runs it.
run_cmd() {
    echo -e "\e[32m $* \e[0m"
    "$@"
}


# ──── Function to validate URL format ───────────────────────────────────────
validate_url() {
    if [[ ! $1 =~ ^(http|https):// ]]; then
        echo "Error: The provided parameter is not a valid URL. It should start with http:// or https://."
        exit 1
    fi
}


# ──── Function to check if required tools are installed ──────────────────────
check_tools() {
    required_tools=(whois dnsrecon whatweb wpscan sqlmap curl nmap sslscan nrich dig dalfox nuclei nikto joomscan)
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
    protonvpn connect --random
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


    # Display ethical use warning
    echo -e "\nWarning: Ensure you have explicit authorization before running these tests. Unauthorized testing is illegal and unethical.\n"

    # Ask user if they want to continue
    read -p "Do you want to continue running the script? (yes/no): " choice
    if [[ "$choice" != "yes" ]]; then
        echo "Exiting script."
        exit 0
    fi


    # Start Date
    echo -e "\n\nStart date: $(date +"%Y-%m-%d %H:%M") \n\n"
		

    # Extract host, domain and IPv4
    host=$(echo "$url" | awk -F[/:] '{print $4}')
    domain=$(echo "$host" | awk -F. '{if (NF>2) {print $(NF-1)"."$NF} else {print $0}}')
    ipv4=$(dig +short "$host" A | head -n1)
    echo "Host=$host"
    echo "Domain=$domain"
    echo "IPv4=$ipv4"
    echo "Url=$url"
    echo -e "\n\n"


    # ──── ProtonVPN ───────────────────────────────────────────────────────────
    VPN="false"
    if command -v protonvpn &> /dev/null; then
        VPN="true"
        echo "ProtonVPN is installed."
        echo -e "\n\n"
    fi


    # ──── Let's go to Work! ───────────────────────────────────────────────────

    vpn_rotate_ip
    random_timeout
    # WHOIS lookup for domain information
    # No evasion available — query goes to registry server, not the target
    echo -e "[+] Running WHOIS lookup..."
    run_cmd sudo whois "$domain"
    echo -e "\n\n"


    vpn_rotate_ip
    random_timeout
    # DNS reconnaissance
    # Using Google and Cloudflare public's DNS (8.8.8.8 and 1.1.1.1) to avoid querying target's nameserver directly
    echo -e "[+] Running DNS reconnaissance..."
    run_cmd dnsrecon --domain "$domain" \
                     --name_server 8.8.8.8,1.1.1.1
    echo -e "\n\n"

    
    vpn_rotate_ip
    random_timeout
    # SSL/TLS scan
    # No evasion available — TLS handshake is inherently identifiable
    echo -e "[+] Running SSL/TLS scan..."
    run_cmd sslscan "$host"
    echo -e "\n\n"

    
    vpn_rotate_ip
    random_timeout
    # HTTP Headers
    # Random User-Agent to blend in with normal browser traffic
    echo -e "[+] Getting HTTP Headers..."
    run_cmd curl "$url" \
                 --head \
                 --user-agent "$USER_AGENT"
    echo -e "\n\n"

	
    vpn_rotate_ip no
    random_timeout
    # Note: Nmap gives incorrect results with VPN enabled
    # Nmap Open Ports and Service detection
    # -f fragments packets, --mtu 16 evades DPI, --data-length adds random padding,
    # -T<0-5>: Set timing template (higher is faster), T3 is default
    # -T2 slows timing to avoid rate-based detection, --randomize-hosts randomizes order
    # https://nmap.org/book/man-performance.html
    echo -e "[+] Nmap Open Ports and Service detection..."
    run_cmd sudo nmap "$host" \
                      -sS \
                      -T3 \
                      --data-length 25 \
                      --max-retries 2 \
                      --source-port 53 \
                      -f \
                      --mtu 16
    echo -e "\n\n"

	
    vpn_rotate_ip no
    random_timeout
    # Note: Nmap gives incorrect results with VPN enabled
    # Nmap vulnerabilities scan
    echo -e "[+] Nmap vulnerabilities scan..."
    run_cmd sudo nmap "$host" \
                      --script vuln \
                      -sS \
                      -T3 \
                      --data-length 25 \
                      --max-retries 2 \
                      --source-port 53 \
                      -D RND:5
    echo -e "\n\n"


    vpn_rotate_ip
    random_timeout
    # Shodan scan (nrich)
    # Passive lookup — no direct contact with target, no evasion needed
    echo -e "[+] Running Shodan scan..."
    run_cmd bash -c "echo \"$ipv4\" | nrich -"
    echo -e "\n\n"


    vpn_rotate_ip
    random_timeout
    # Identify technologies used on the website
    # --aggression 1 = stealthy mode (single request, passive fingerprinting)
    echo -e "[+] Identifying technologies used on the website..."
    whatweb_output=$(whatweb --aggression 1 -U "$USER_AGENT" "$url")
    run_cmd whatweb --aggression 1 -U "$USER_AGENT" "$url"
    echo -e "\n\n"


    # Wordpress vulnerability scan (only if WordPress detected by whatweb)
    # --stealthy enables passive mode (no aggressive probing)
    echo -e "[+] Checking for WordPress..."
    if echo "$whatweb_output" | grep -qi "wordpress"; then
        vpn_rotate_ip
        random_timeout
        echo -e "[!] WordPress detected — running wpscan..."
        run_cmd sudo wpscan --url "$url" \
                            --update \
                            --no-banner \
                            --stealthy
    else
        echo -e "[-] WordPress not detected — skipping wpscan."
    fi
    echo -e "\n\n"


    # Joomla vulnerability scan (only if Joomla detected by whatweb)
    echo -e "[+] Checking for Joomla..."
    if echo "$whatweb_output" | grep -qi "joomla"; then
        vpn_rotate_ip
        random_timeout
        echo -e "[!] Joomla detected — running joomscan..."
        run_cmd sudo joomscan -u "$url" \
                              --random-agent \
                              --timeout 600
    else
        echo -e "[-] Joomla not detected — skipping joomscan."
    fi
    echo -e "\n\n"
	

    vpn_rotate_ip
    random_timeout
    # Host header injection test
    # Random User-Agent added to blend in with normal browser traffic
    echo -e "[+] Running Host header injection test..."
    run_cmd curl -s -o /dev/null -w "%{http_code}" \
                 -A "$USER_AGENT" \
                 -H "Host: malicious.example.com" "$url"
    host_header_injection_status=$(curl -s -o /dev/null -w "%{http_code}" \
        -A "$USER_AGENT" \
        -H "Host: malicious.example.com" "$url")
    echo -e "Host header injection test, HTTP code: $host_header_injection_status"
    if [ "$host_header_injection_status" -eq 200 ]; then
        echo -e " Vulnerable "
    fi
    echo -e "\n\n"


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
    # -rate-limit 10 slows requests to avoid triggering rate-based WAF rules, (default 150)
    # -concurrency 10 slows requests templates to be executed in parallel (default 25)
    # -timeout 15 -retries 3 -no-mhe, 15s before timeout, 3 retries and don't skip unresponsive hosts
    # timeout 2700, kill nuclei after 2700 seconds
    # -random-agent rotates User-Agent per request
    echo -e "[+] Nuclei vulnerabilities scan..."
    run_cmd timeout 2700 \
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
    # -evasion 1234678 applies all available evasion techniques:
    #   1=random URI encoding, 2=directory self-reference (/./),
    #   3=premature URL ending (%00), 4=prepend long random string,
    #   6=TAB as request spacer, 7=random case sensitivity,
    #   8=Windows path separator (\)
    # -useragent: spoofs a real browser UA
    # -maxtime 1800: cap scan at 30 minutes
    # Nikto has no -H flag for custom headers. WAF-bypass headers are injected
    #   by appending them to -useragent separated by \r\n — nikto places the
    #   UA string verbatim into the request, so \r\n starts a new header line.
    NIKTO_UA="${USER_AGENT}\r\nX-Forwarded-For: 127.0.0.1\r\nX-Real-IP: 127.0.0.1\r\nX-Originating-IP: 127.0.0.1\r\nAccept-Language: en-US,en;q=0.9\r\nReferer: https://www.google.com/"
    echo -e "[+] Nikto vulnerabilities scan..."
    run_cmd nikto -h "$url" \
                  -maxtime 1800 \
                  -evasion 1234678 \
                  -useragent "$NIKTO_UA"
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
    run_cmd sqlmap -u "$url" \
                   --batch \
                   --random-agent \
                   --delay=3 \
                   --level=3 \
                   --risk=2 \
                   --hpp \
                   --hex \
                   --tamper=space2comment,between,randomcase,charunicodeencode,charencode,equaltolike,multiplespaces,percentage,unmagicquotes
    echo -e "\n\n"


    # End Date
    echo -e "End date: $(date +"%Y-%m-%d %H:%M") \n\n"
}

# Execute main function
main "$@"
