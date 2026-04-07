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
   - [Npm](#npm)
   - [Nuclei](#nuclei)
   - [Proton VPN](#protonvpn)
   - [Shodan nrich](#shodan-nrich)
   - [Sqlmap](#sqlmap)
   - [Sslscan](#sslscan)
   - [Sslyze](#sslyze)
   - [Whatweb](#whatweb)
   - [Whois](#whois)
   - [WPScan](#wpscan)
   - [ZAProxy](#zaproxy)
   - [isMyWebsiteInsecure](#isMyWebsiteInsecure)


---

## 1. Libraries Installation

```bash
sudo apt update && sudo apt dist-upgrade -y && sudo reboot
```

```bash
sudo apt update && sudo apt upgrade -y && sudo apt autoremove -y
```

```bash
# Kali only
# https://snapcraft.io/docs/tutorials/install-the-daemon/kali/

sudo apt install -y snapd

sudo systemctl enable snapd
sudo systemctl enable snapd.apparmor

sudo reboot

sudo systemctl start snapd.apparmor
sudo systemctl start snapd

sudo systemctl status snapd.apparmor
sudo systemctl status snapd
```

---

## 2. Tools Installation

```bash
sudo apt update && sudo apt upgrade -y && sudo apt autoremove -y
```

```bash
sudo snap refresh
```

```bash
# only to run isMyWebsiteInsecure-2.sh script
sudo visudo
 # add following line to change default timestamp_timeout from 60 min to 270 min
 Defaults timestamp_timeout=270
```

### Chromium

> Website: [https://www.chromium.org/Home/](https://www.chromium.org/Home/)  
> Releases: []()  

```bash
# Kali installation
sudo apt install -y chromium
chromium --version
```

```bash
# Ubuntu installation
sudo snap install chromium
chromium --version
```

### Curl

> Website: [https://curl.se/](https://curl.se/)  
> Releases: [https://curl.se/download.html](https://curl.se/download.html)  

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
> Go to https://NESSUS_HOSTNAME_OR_IP:8834/ to configure your scanner, ex: https://127.0.0.1:8834/

```bash
cd $HOME/Downloads
wget https://www.tenable.com/downloads/api/v2/pages/nessus/files/Nessus-10.11.3-ubuntu1604_amd64.deb
sudo dpkg -i Nessus-10.11.3-ubuntu1604_amd64.deb
sudo /bin/systemctl start nessusd.service
```

### Nikto

> Website: [https://cirt.net/Nikto2](https://cirt.net/Nikto2)  
> Releases: [https://github.com/sullo/nikto/releases](https://github.com/sullo/nikto/releases)  

```bash
# Kali installation
sudo apt install -y nikto
nikto -Version
```

```bash
# Ubuntu installation
# to update: git pull
sudo apt install -y cpanminus && sudo cpanm JSON && sudo cpanm XML::Writer
git clone --depth 1 https://github.com/sullo/nikto.git $HOME/tools/nikto 
sudo ln -s $HOME/tools/nikto/program/nikto.pl /usr/local/bin/nikto
nikto -Version
```


### Nmap

> Website: [https://nmap.org/](https://nmap.org/)  
> Releases: [https://nmap.org/download.html#linux-rpm](https://nmap.org/download.html#linux-rpm)  

```bash
sudo apt install -y nmap
nmap --version
```

### Npm

> Website: [https://docs.npmjs.com/about-npm](https://docs.npmjs.com/about-npm)  
> Releases: [https://docs.npmjs.com/cli/v11/commands/npm-install](https://docs.npmjs.com/cli/v11/commands/npm-install)  

```bash
sudo apt install -y npm
npm --version
```


### Nuclei

> Website: [https://projectdiscovery.io/nuclei](https://projectdiscovery.io/nuclei)  
> Releases: [https://github.com/projectdiscovery/nuclei/releases](https://github.com/projectdiscovery/nuclei/releases)  

```bash
# Kali installation
sudo apt install -y nuclei
nuclei
```

```bash
# Ubuntu installation
sudo snap install go --classic
go version        # verify installation

# on /etc/profile, add at the end, export GOPATH=$HOME/tools/go
mkdir -p "$HOME/tools/go"
if ! grep -Fxq "export GOPATH=\$HOME/tools/go" /etc/profile; then echo "export GOPATH=\$HOME/tools/go" | sudo tee -a /etc/profile > /dev/null; echo "Added to /etc/profile"; else echo "Line already exists in /etc/profile."; fi
source /etc/profile
echo $GOPATH

go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
sudo ln -s $HOME/tools/go/bin/nuclei /usr/bin/nuclei
nuclei
```

### ProtonVPN

> Reference: [https://protonvpn.com/support/official-linux-vpn-ubuntu](https://protonvpn.com/support/official-linux-vpn-ubuntu)  
> CLI docs: [https://protonvpn.com/support/linux-cli](https://protonvpn.com/support/linux-cli)  

```bash
# Ubuntu optional installation. A paid license is required.
# Not work on Kali Linux.
cd $HOME/Downloads
wget https://repo.protonvpn.com/debian/dists/stable/main/binary-all/protonvpn-stable-release_1.0.8_all.deb
sudo dpkg -i ./protonvpn-stable-release_1.0.8_all.deb
sudo apt update
sudo apt install -y proton-vpn-cli
protonvpn --help
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

sudo apt-get install -y ruby-full rubygems

sudo gem install wpscan
wpscan --version
```

### ZAProxy

> Website: [https://www.zaproxy.org/](https://www.zaproxy.org/)  
> Downloads: [https://www.zaproxy.org/download/](https://www.zaproxy.org/download/)   

```bash
# Kali installation
sudo apt install -y zaproxy
zaproxy -version
```

```bash
# Ubuntu installation
# To update: `sudo snap refresh zaproxy`
sudo snap install zaproxy --classic
zaproxy -version
```

### isMyWebsiteInsecure

> scripts that detect vulnerabilities in websites:  
>  \- isMyWebsiteInsecure-1.sh , using public free web tools.  
>  \- isMyWebsiteInsecure-2.sh , using public free command-line tools.  
>  TIP: both must be used  

```
mkdir $HOME/tools   # tools folder
cd $HOME/tools
rm -f isMyWebsiteInsecure-*.sh 
wget https://raw.githubusercontent.com/oazevedo/isMyWebsiteInsecure/main/Linux/isMyWebsiteInsecure-1.sh
wget https://raw.githubusercontent.com/oazevedo/isMyWebsiteInsecure/main/Linux/isMyWebsiteInsecure-2.sh
chmod +x isMyWebsiteInsecure-*.sh
```
