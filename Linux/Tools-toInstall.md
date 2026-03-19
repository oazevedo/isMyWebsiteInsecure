# Tools to install

## Index

1. [Libraries Installation](#1-libraries-installation)
2. [Tools Installation](#2-tools-installation)
   - [Chromium](#chromium)
   - [Curl](#curl)
   - [Dalfox](#dalfox)
   - [Dnsrecon](#dnsrecon)
   - [Nessus](#nessus)
   - [Nikto](#nikto)
   - [Nmap](#nmap)
   - [Nuclei](#nuclei)
   - [Shodan nrich](#shodan-nrich)
   - [Sqlmap](#sqlmap)
   - [Sslscan](#sslscan)
   - [Sslyze](#sslyze)
   - [Whatweb](#whatweb)
   - [Whois](#whois)
   - [WPScan](#wpscan)
   - [ZAProxy](#zaproxy)
   - [isMyWebsiteInsecure](#ismywebsiteinsecure)
   - [ProtonVPN CLI *(Optional - only for Ubuntu)*](#protonvpn-cli-optional)

---

## 1. Libraries Installation

```bash
sudo apt update && sudo apt dist-upgrade
```

```bash
sudo apt update && sudo apt upgrade -y && sudo apt autoremove -y
```

```bash
sudo apt install -y snapd
sudo systemctl enable snapd
sudo systemctl start snapd
sudo systemctl status snapd
sudo snap refresh
```

```bash
# Ubuntu only: need for WPScan installation
# Gem is a Ruby package manager and comes bundled with Ruby.
sudo apt install -y ruby-full
```

```bash
sudo apt install -y git
```

```bash
sudo apt install -y libcurl4-openssl-dev
```

```bash
sudo apt install -y python-is-python3
```

```bash
sudo apt install -y perl libwww-perl libnet-ssleay-perl
```

```bash
# Need for Nikto installation 
sudo apt install -y cpanminus && sudo cpanm JSON && sudo cpanm XML::Writer
```

```bash
# Install only on Ubuntu?, Kaly já vem instalado? verificar.
sudo snap install go --classic
go version        # verify installation
```

---

## 2. Tools Installation

```bash
mkdir $HOME/tools             # tools folder
```

```bash
sudo apt update && sudo apt upgrade -y && sudo apt autoremove -y
```

### Chromium

> Website: [https://www.chromium.org/Home/](https://www.chromium.org/Home/)  
> Releases: []()  
> To update: `sudo snap refresh dalfox`

```bash
sudo snap install chromium
chromium version
```

### Curl

> Website: [https://curl.se/](https://curl.se/)  
> Releases: [https://github.com/curl/curl/releases](https://github.com/curl/curl/releases)  

```bash
sudo apt install -y curl
curl --version
```

### Dalfox

> Website: [https://dalfox.hahwul.com/](https://dalfox.hahwul.com/)  
> Releases: [https://github.com/hahwul/dalfox/releases](https://github.com/hahwul/dalfox/releases)  
> To update: `sudo snap refresh dalfox`

```bash
sudo snap install dalfox
dalfox version
```

### Dnsrecon

> Website: [https://github.com/darkoperator/dnsrecon](https://github.com/darkoperator/dnsrecon)  
> Releases: [https://github.com/darkoperator/dnsrecon/releases](https://github.com/darkoperator/dnsrecon/releases)  

```bash
sudo apt install -y dnsrecon
dnsrecon --version
```

### Nessus

> Website: [https://www.tenable.com/products/nessus](https://www.tenable.com/products/nessus)  
> Releases: [https://www.tenable.com/downloads/nessus?loginAttempted=true](https://www.tenable.com/downloads/nessus?loginAttempted=true)  
> To update:  

```bash
cd $HOME/Downloads
curl --request GET \ --url 'https://www.tenable.com/downloads/api/v2/pages/nessus/files/Nessus-10.11.3-ubuntu1604_amd64.deb' \ --output 'Nessus-10.11.3-ubuntu1604_amd64.deb'
sudo dpkg -i Nessus-10.11.3-ubuntu1604_amd64.deb
sudo /bin/systemctl start nessusd.service
# go to https://NESSUS_HOSTNAME_OR_IP:8834/ to configure your scanner, ex: https://127.0.0.1:8834/
```

### Nikto

> Website: [https://cirt.net/Nikto2](https://cirt.net/Nikto2)  
> Releases: [https://github.com/sullo/nikto/releases](https://github.com/sullo/nikto/releases)  
> To update: `git pull`  
> To enable global access: `ln -s`

```bash
sudo apt remove -y nikto
git clone --depth 1 https://github.com/sullo/nikto.git $HOME/tools/nikto
sudo ln -s $HOME/tools/nikto/program/nikto.pl /usr/bin/nikto
nikto -Version
```

### Nmap

> Website: [https://nmap.org/](https://nmap.org/)  
> Releases: [https://nmap.org/download.html#linux-rpm](https://nmap.org/download.html#linux-rpm)  

```bash
sudo apt install -y nmap
nmap --version
```

### Nuclei

> Website: [https://projectdiscovery.io/nuclei](https://projectdiscovery.io/nuclei)  
> Releases: [https://github.com/projectdiscovery/nuclei/releases](https://github.com/projectdiscovery/nuclei/releases)  
> To enable global access: `ln -s`

```bash
# Kali installation
sudo apt install -y nuclei
nuclei
```

```bash
# Ubuntu installation
if ! grep -Fxq "export GOPATH=\$HOME/tools/go" /etc/profile; then echo "export GOPATH=\$HOME/tools/go" | sudo tee -a /etc/profile > /dev/null; echo "Added to /etc/profile"; else echo "Line already exists in /etc/profile."; fi
source /etc/profile

go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
sudo ln -s $HOME/tools/go/bin/nuclei /usr/bin/nuclei
nuclei
```

### Shodan nrich

> Website: [https://gitlab.com/shodan-public/nrich](https://gitlab.com/shodan-public/nrich)  
> Releases: [https://gitlab.com/shodan-public/nrich/-/releases](https://gitlab.com/shodan-public/nrich/-/releases)  

```bash
sudo snap install nrich
nrich --version
```

### Sqlmap

> Website: [https://sqlmap.org/](https://sqlmap.org/)  
> Releases: [https://github.com/sqlmapproject/sqlmap/releases](https://github.com/sqlmapproject/sqlmap/releases)  

```bash
sudo apt install -y sqlmap
sqlmap --version
```

### Sslscan

> Website: [https://github.com/rbsec/sslscan](https://github.com/rbsec/sslscan)  
> Releases: [https://github.com/rbsec/sslscan/releases](https://github.com/rbsec/sslscan/releases)  

```bash
sudo apt install -y sslscan
sslscan --version
```

### Sslyze

> Website: [https://github.com/nabla-c0d3/sslyze](https://github.com/nabla-c0d3/sslyze)  
> Releases: [https://github.com/nabla-c0d3/sslyze/releases](https://github.com/nabla-c0d3/sslyze/releases)  

```bash
# Kali installation
sudo apt install -y sslyze
sslyze --help | grep -i "sslyze version"
```

### Whatweb

> Website: [https://morningstarsecurity.com/research/whatweb](https://morningstarsecurity.com/research/whatweb)  
> Releases: [https://github.com/urbanadventurer/WhatWeb/releases](https://github.com/urbanadventurer/WhatWeb/releases)  

```bash
sudo apt install -y whatweb
whatweb --version
```

### Whois

> Website: [https://github.com/rfc1036/whois](https://github.com/rfc1036/whois)  
> Releases: [https://github.com/rfc1036/whois/tags](https://github.com/rfc1036/whois/tags)

```bash
sudo apt install -y whois
whois --version
```

### WPScan

> Website: [https://wpscan.com/](https://wpscan.com/)  
> Releases: [https://github.com/wpscanteam/wpscan/releases](https://github.com/wpscanteam/wpscan/releases)  

```bash
# Kali installation
sudo apt install -y wpscan
wpscan --version
```

```bash
# Ubuntu installation
# To update: `sudo gem update wpscan`
sudo gem install wpscan
wpscan --version
```

### ZAProxy

> Website: [https://www.zaproxy.org/](https://www.zaproxy.org/)  
> Downloads: [https://www.zaproxy.org/download/](https://www.zaproxy.org/download/)   
> To update: `sudo snap refresh zaproxy`

```bash
sudo snap install zaproxy --classic
```

### isMyWebsiteInsecure

> Repository: [https://github.com/oazevedo/isMyWebsiteInsecure](https://github.com/oazevedo/isMyWebsiteInsecure)  
> `raw.githubusercontent.com` downloads the file directly as it is intended to be used (e.g., a shell script, text file, etc.)

```bash
cd $HOME/tools
rm -f isMyWebsiteInsecure-*.sh
wget https://raw.githubusercontent.com/oazevedo/isMyWebsiteInsecure/main/Linux/isMyWebsiteInsecure-1.sh
wget https://raw.githubusercontent.com/oazevedo/isMyWebsiteInsecure/main/Linux/isMyWebsiteInsecure-2.sh
chmod +x isMyWebsiteInsecure-*.sh
```

### ProtonVPN CLI *(Optional - only for Ubuntu)*

> Reference: [https://protonvpn.com/support/official-linux-vpn-ubuntu](https://protonvpn.com/support/official-linux-vpn-ubuntu)  
> CLI docs: [https://protonvpn.com/support/linux-cli](https://protonvpn.com/support/linux-cli)

```bash
# Ubuntu installation
cd $HOME/Downloads
wget https://repo.protonvpn.com/debian/dists/stable/main/binary-all/protonvpn-stable-release_1.0.8_all.deb
sudo dpkg -i ./protonvpn-stable-release_1.0.8_all.deb
sudo apt update
sudo apt install -y proton-vpn-cli
protonvpn --help
```
