#!/bin/bash
# isMyWebsiteInsecure-2.sh
# developed by Oscar Azevedo, oscar.azevedo@aeportugal.pt, oscar.msazevedo@gmail.com
# v1.0

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

    firefox --new-window --private-window "$url"
    sleep 2

    firefox --new-tab --private-window "https://pentest-tools.com/network-vulnerability-scanning/tcp-port-scanner-online-nmap/"
    sleep 2

    firefox --new-tab --private-window "https://www.wpsec.com/"
    sleep 2

    firefox --new-tab --private-window "https://sitecheck.sucuri.net/results/$host"
    sleep 2

    firefox --new-tab --private-window "https://powerdmarc.com/dkim-record-lookup/"
    sleep 2

    firefox --new-tab --private-window "https://domain-checker.valimail.com/dmarc/$domain"
    sleep 2

    firefox --new-tab --private-window "https://www.ssllabs.com/ssltest/analyze.html?d=$url&hideResults=on&latest"
    sleep 2

    firefox --new-tab --private-window "https://securityheaders.com/?followRedirects=on&hide=on&q=$url"
    sleep 2

    firefox --new-tab --private-window "https://report-uri.com/"
    sleep 2

    firefox --new-tab --private-window "https://developer.mozilla.org/en-US/observatory/analyze?host=$host"
    sleep 2

    firefox --new-tab --private-window "https://internet.nl/site/$host/"
    sleep 2

    firefox --new-tab --private-window "https://www.immuniweb.com/websec/"
    sleep 2

    firefox --new-tab --private-window "https://pentest-tools.com/website-vulnerability-scanning/website-scanner"
    sleep 2

    firefox --new-tab --private-window "https://www.zaproxy.org/"
    sleep 2

    firefox --new-tab --private-window "https://www.tenable.com/products/nessus/nessus-essentials"
    sleep 2

    firefox --new-tab --private-window "https://snyk.io/product/snyk-code/"
    sleep 2

    firefox --new-tab --private-window "https://www.cookiebot.com/en/compliance-test/?domain=$host"
    sleep 2

    firefox --new-tab --private-window "https://developers.google.com/speed/pagespeed/insights/?url=$url"
    sleep 2

    firefox --new-tab --private-window "https://validator.w3.org/nu/?showsource=no&doc=$url/"
    sleep 2

    firefox --new-tab --private-window "https://jigsaw.w3.org/css-validator/validator?uri=$url&profile=css3svg&usermedium=all&warning=1&vextwarning=&lang=en"
    sleep 2
}

# Execute main function
main "$@"
    

