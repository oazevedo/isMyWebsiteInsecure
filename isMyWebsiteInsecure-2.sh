#!/bin/bash
# isMyWebsiteInsecure-2.sh
# developed by Oscar Azevedo, oscar.azevedo@aeportugal.pt, oscar.msazevedo@gmail.com
# check the security of a given website with public command line tools
#
# nmap: don't use with vpn because returns wrong results
#
# v1.4, modified on 2026-02-22
#  - added rotate_ip using Proton VPN
#  - added evasion capability
#

# ──── Evasion User-Agent ──────────────────────────────────────────────────────
USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"


# Function to validate URL format
validate_url() {
    if [[ ! $1 =~ ^(http|https):// ]]; then
        echo "Error: The provided parameter is not a valid URL. It should start with http:// or https://."
        exit 1
    fi
}


# Function to check if required tools are installed
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


# Function to rotate VPN public IP Address
vpn_rotate_ip() {
    if [[ "$VPN" != "true" ]]; then
        return 0
    fi

    sleep 10
    echo -e "\e[36m[*] ProtonVPN — switching to a new random server...\e[0m"
    protonvpn connect --random
    sleep 15
}


# Main script
main() {

    # Check if a URL parameter is provided
    if [ "$#" -ne 1 ]; then
        echo -e "\e[32mUsage: $0 <url>\e[0m"
        exit 1
    fi


    # Display ethical use warning
    echo -e "\n\e[31mWarning: Ensure you have explicit authorization before running these tests. Unauthorized testing is illegal and unethical.\e[0m\n"

    # Ask user if they want to continue
    read -p "Do you want to continue running the script? (yes/no): " choice
    if [[ "$choice" != "yes" ]]; then
        echo "Exiting script."
        exit 0
    fi


    # Validate the URL format
    url="$1"
    validate_url "$url"


    # Check if required tools are installed
    check_tools


    # Extract host, domain and IPv4
    host=$(echo "$url" | awk -F[/:] '{print $4}')
    domain=$(echo "$host" | awk -F. '{if (NF>2) {print $(NF-1)"."$NF} else {print $0}}')
    ipv4=$(dig +short "$host" A | head -n1)
    echo
    echo "Host=$host"
    echo "Domain=$domain"
    echo "IPv4=$ipv4"
    echo "Url=$url"
    echo


    # ──── ProtonVPN ───────────────────────────────────────────────────────────
    VPN="false"
    if command -v protonvpn &> /dev/null; then
        VPN="true"
		protonvpn disconnect
		sleep 10
        echo "ProtonVPN is installed."
		echo -e "\n\n"
    fi


    # ──── Let's go to Work! ───────────────────────────────────────────────────

    # WHOIS lookup for domain information
    # No evasion available — query goes to registry server, not the target
    echo -e "\e[38;5;208m[+] Running WHOIS lookup...\e[0m"
    echo -e "\e[32m sudo whois \"$domain\" \e[0m"
    sudo whois "$domain"
    echo -e "\n\n"


    # DNS reconnaissance
    # Using Google and Cloudflare public's DNS (8.8.8.8 and 1.1.1.1) to avoid querying target's nameserver directly
    echo -e "\e[38;5;208m[+] Running DNS reconnaissance...\e[0m"
    echo -e "\e[32m dnsrecon -d \"$domain\" -n 8.8.8.8,1.1.1.1 \e[0m"
    dnsrecon -d "$domain" -n 8.8.8.8,1.1.1.1
    echo -e "\n\n"


    # SSL/TLS scan
    # No evasion available — TLS handshake is inherently identifiable
    echo -e "\e[38;5;208m[+] Running SSL/TLS scan...\e[0m"
    echo -e "\e[32m sslscan \"$host\" \e[0m"
    sslscan "$host"
    echo -e "\n\n"


    # HTTP Headers
    # Random User-Agent to blend in with normal browser traffic
    echo -e "\e[38;5;208m[+] Getting HTTP Headers...\e[0m"
    echo -e "\e[32m curl -I -A \"<user-agent>\" \"$url\" \e[0m"
    curl -I -A "$USER_AGENT" "$url"
    echo -e "\n\n"


    # Nmap Open Ports and Service detection
    # -f fragments packets, --mtu 16 evades DPI, --data-length adds random padding,
    # -T2 slows timing to avoid rate-based detection, --randomize-hosts randomizes order
    echo -e "\e[38;5;208m[+] Nmap Open Ports and Service detection...\e[0m"
    echo -e "\e[32m sudo nmap -sS -sV -f --mtu 16 --data-length 25 -T2 --randomize-hosts \"$host\" \e[0m"
    sudo nmap -sS -sV -f --mtu 16 --data-length 25 -T2 --randomize-hosts "$host"
    echo -e "\n\n"


    # Nmap vulnerabilities scan
    echo -e "\e[38;5;208m[+] Nmap vulnerabilities scan...\e[0m"
    echo -e "\e[32m sudo nmap -sS --script vuln -f --mtu 16 --data-length 25 -T2 --randomize-hosts \"$host\" \e[0m"
    sudo nmap -sS --script vuln -f --mtu 16 --data-length 25 -T2 --randomize-hosts "$host"
    echo -e "\n\n"


    vpn_rotate_ip
    # Shodan scan (nrich)
    # Passive lookup — no direct contact with target, no evasion needed
    echo -e "\e[38;5;208m[+] Running Shodan scan...\e[0m"
    echo -e "\e[32m echo \"$ipv4\" | nrich - \e[0m"
    echo "$ipv4" | nrich -
    echo -e "\n\n"


    vpn_rotate_ip
    # Identify technologies used on the website
    # --aggression 1 = stealthy mode (single request, passive fingerprinting)
    echo -e "\e[38;5;208m[+] Identifying technologies used on the website...\e[0m"
    echo -e "\e[32m whatweb --aggression 1 -U \"<user-agent>\" \"$url\" \e[0m"
    whatweb_output=$(whatweb --aggression 1 -U "$USER_AGENT" "$url")
    echo "$whatweb_output"
    echo -e "\n\n"


    vpn_rotate_ip
    # Wordpress vulnerability scan — only if WordPress is detected
    # --stealthy enables passive mode (no aggressive probing)
    echo -e "\e[38;5;208m[+] Checking for WordPress...\e[0m"
    if echo "$whatweb_output" | grep -qi "wordpress"; then
        echo -e "\e[33m[!] WordPress detected — running WPScan...\e[0m"
        echo -e "\e[32m sudo wpscan --update --no-banner --stealthy --url \"$url\" \e[0m"
        sudo wpscan --update --no-banner --stealthy --url "$url"
    else
        echo -e "\e[32m[*] WordPress not detected — skipping WPScan.\e[0m"
    fi
    echo -e "\n\n"


    vpn_rotate_ip
    # Host header injection test
    # Random User-Agent added to blend in with normal browser traffic
    echo -e "\e[38;5;208m[+] Running Host header injection test...\e[0m"
    echo -e "\e[32m curl -s -A \"<user-agent>\" -H \"Host: malicious.example.com\" \"$url\" \e[0m"
    host_header_injection_status=$(curl -s -o /dev/null -w "%{http_code}" \
        -A "$USER_AGENT" \
        -H "Host: malicious.example.com" "$url")
    echo -e "Host header injection test, HTTP code: $host_header_injection_status"
    if [ "$host_header_injection_status" -eq 200 ]; then
        echo -e "\e[31m Vulnerable \e[0m"
    fi
    echo -e "\n\n"


    vpn_rotate_ip
    # Dalfox XSS Scanner
    # --waf-evasion already applied
    echo -e "\e[38;5;208m[+] Dalfox xss scan...\e[0m"
    echo -e "\e[32m dalfox --waf-evasion url \"$url\" \e[0m"
    dalfox --waf-evasion url "$url"
    echo -e "\n\n"


    vpn_rotate_ip
    # Nuclei vulnerabilities scan
    # -rate-limit 10 slows requests to avoid triggering rate-based WAF rules
    # -random-agent rotates User-Agent per request
    echo -e "\e[38;5;208m[+] Nuclei vulnerabilities scan...\e[0m"
	echo -e "\e[32m nuclei -u \"$url\" -rate-limit 10 -H \"User-Agent: <ua>\" -H \"X-Forwarded-For: 127.0.0.1\" -H \"Referer: https://google.com\" \e[0m"
	nuclei -u "$url" -rate-limit 10 -H "User-Agent: $USER_AGENT" -H "X-Forwarded-For: 127.0.0.1" -H "Referer: https://google.com"
    echo -e "\n\n"


    vpn_rotate_ip
    # Nikto vulnerabilities scan
    # -evasion 1234678 applies multiple evasion techniques:
    #   1=random URI encoding, 2=directory self-reference, 3=premature URL ending,
    #   4=prepend long random string, 6=TAB as request spacer,
    #   7=random case sensitivity, 8=Windows path separator
    echo -e "\e[38;5;208m[+] Nikto vulnerabilities scan...\e[0m"
    echo -e "\e[32m nikto -h \"$url\" -useragent \"<user-agent>\" -evasion 1234678 \e[0m"
    nikto -h "$url" -useragent "$USER_AGENT" -evasion 1234678
    echo -e "\n\n"


    vpn_rotate_ip
    # SQLmap check for SQL injection
    # --random-agent rotates User-Agent, --delay=2 adds delay between requests,
    # --tamper applies payload obfuscation to bypass WAF signature matching
    echo -e "\e[38;5;208m[+] SQLmap check for SQL injection\e[0m"
    echo -e "\e[32m sqlmap --batch --random-agent --delay=2 --tamper=space2comment,between,randomcase -u \"$url\" \e[0m"
    sqlmap --batch --random-agent --delay=2 --tamper=space2comment,between,randomcase -u "$url"
    echo -e "\n\n"
}

# Execute main function
main "$@"
