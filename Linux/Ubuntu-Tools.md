# Ubuntu Tools

## Index

1. [Libraries Installation](#1-libraries-installation)
2. [Tools Installation](#2-tools-installation)
   - [APT Tools (curl, dnsrecon, sqlmap, sslscan, whatweb)](#apt-tools-curl-dnsrecon-sqlmap-sslscan-whatweb)
   - [Dalfox](#dalfox)
   - [Nikto](#nikto)
   - [Nmap](#nmap)
   - [Nuclei](#nuclei)
   - [Shodan nrich](#shodan-nrich)
   - [Whois](#whois)
   - [WPScan](#wpscan)
   - [ZAProxy](#zaproxy)
   - [isMyWebsiteInsecure](#ismywebsiteinsecure)
   - [ProtonVPN CLI *(Optional)*](#protonvpn-cli-optional)

---

## 1. Libraries Installation

```bash
sudo apt update && sudo apt upgrade -y && sudo apt autoremove -y
```

```bash
sudo snap refresh
```

```bash
# Gem is a Ruby package manager and comes bundled with Ruby.
sudo apt install -y ruby-full
```

```bash
sudo gem update
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
sudo apt install -y alien
```

```bash
sudo apt install -y cpanminus && sudo cpanm JSON && sudo cpanm XML::Writer
```

### Go Installation

> Always check what is the latest version.  
> Reference: [https://go.dev/doc/install](https://go.dev/doc/install) — Release History - The Go Programming Language

```bash
sudo rm -rf /usr/local/go
cd $HOME/Downloads
wget https://go.dev/dl/go1.26.1.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.26.1.linux-amd64.tar.gz
sudo nano /etc/profile        # add at end of file
  export PATH=$PATH:/usr/local/go/bin
  export GOPATH=$HOME/tools/go
go version                    # verify installation
```

---

## 2. Tools Installation

```bash
mkdir $HOME/tools             # tools folder
```

```bash
sudo apt update && sudo apt upgrade -y && sudo apt autoremove -y
```

### APT Tools (curl, dnsrecon, sqlmap, sslscan, whatweb)

> Note: apt versions may be outdated — check GitHub for latest releases.

```bash
sudo apt install -y curl dnsrecon sqlmap sslscan whatweb
curl --version       # https://github.com/curl/curl/releases
dnsrecon --version   # outdated version, see https://github.com/darkoperator/dnsrecon/releases
sqlmap --version     # outdated version, see https://github.com/sqlmapproject/sqlmap/releases
sslscan --version    # outdated version, see https://github.com/rbsec/sslscan/releases
whatweb --version    # outdated version, see https://github.com/urbanadventurer/WhatWeb/releases
```

### Dalfox

> Releases: [https://github.com/hahwul/dalfox/releases](https://github.com/hahwul/dalfox/releases)  
> To update: `sudo snap refresh dalfox`

```bash
sudo snap install dalfox
dalfox --version
```

### Nikto

> Releases: [https://github.com/sullo/nikto/releases](https://github.com/sullo/nikto/releases)  
> To update: `git pull`  
> To enable global access: `ln -s`

```bash
git clone --depth 1 https://github.com/sullo/nikto.git $HOME/tools/nikto
sudo ln -s $HOME/tools/nikto/program/nikto.pl /usr/local/bin/nikto
nikto -Version
```

### Nmap

> Always check what is the latest version.
> Reference: [https://nmap.org/download.html#linux-rpm](https://nmap.org/download.html#linux-rpm)  
> `alien` is used to convert rpm to deb.

```bash
cd $HOME/Downloads
wget https://nmap.org/dist/nmap-7.98-1.x86_64.rpm
sudo alien -k nmap-7.98-1.x86_64.rpm
sudo dpkg -i nmap_7.98-1_amd64.deb
nmap --version
```

### Nuclei

> Releases: [https://github.com/projectdiscovery/nuclei/releases](https://github.com/projectdiscovery/nuclei/releases)  
> To enable global access: `ln -s`

```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
sudo ln -s $HOME/tools/go/bin/nuclei /usr/local/bin/nuclei
nuclei --version
```

### Shodan nrich

> Releases: [https://gitlab.com/shodan-public/nrich/-/releases](https://gitlab.com/shodan-public/nrich/-/releases)  

```bash
cd $HOME/Downloads
wget https://gitlab.com/api/v4/projects/33695681/packages/generic/nrich/latest/nrich_latest_x86_64.deb
sudo dpkg -i nrich_latest_x86_64.deb
nrich --version
```

### Whois

> Always check what is the latest version.
> Releases: [https://github.com/rfc1036/whois/tags](https://github.com/rfc1036/whois/tags)

```bash
cd $HOME/Downloads
wget https://ftp.debian.org/debian/pool/main/w/whois/whois_5.6.6_amd64.deb
sudo dpkg -i whois_5.6.6_amd64.deb
whois --version
```

### WPScan

> Releases: [https://github.com/wpscanteam/wpscan/releases](https://github.com/wpscanteam/wpscan/releases)  
> To update: `sudo gem update wpscan`

```bash
sudo gem install wpscan
wpscan --version
```

### ZAProxy

> Website: [https://www.zaproxy.org/](https://www.zaproxy.org/)  
> Downloads: [https://www.zaproxy.org/download/](https://www.zaproxy.org/download/) — Install with snap is officially supported.  
> To update: `sudo snap refresh zaproxy`

```bash
sudo snap install zaproxy --classic
```

### isMyWebsiteInsecure

> Repository: [https://github.com/oazevedo/isMyWebsiteInsecure](https://github.com/oazevedo/isMyWebsiteInsecure)
> Note: change `/oazevedo/` to `/si-aeportugal/`
> `raw.githubusercontent.com` downloads the file directly as it is intended to be used (e.g., a shell script, text file, etc.)

```bash
cd $HOME/tools
rm -f isMyWebsiteInsecure-*.sh
wget https://raw.githubusercontent.com/oazevedo/isMyWebsiteInsecure/main/isMyWebsiteInsecure-1.sh
wget https://raw.githubusercontent.com/oazevedo/isMyWebsiteInsecure/main/isMyWebsiteInsecure-2.sh
chmod +x isMyWebsiteInsecure-*.sh
isMyWebsiteInsecure-1.sh --version
isMyWebsiteInsecure-2.sh --version
```

### ProtonVPN CLI *(Optional)*

> Reference: [https://protonvpn.com/support/official-linux-vpn-ubuntu](https://protonvpn.com/support/official-linux-vpn-ubuntu)  
> CLI docs: [https://protonvpn.com/support/linux-cli](https://protonvpn.com/support/linux-cli)

```bash
cd $HOME/Downloads
wget https://repo.protonvpn.com/debian/dists/stable/main/binary-all/protonvpn-stable-release_1.0.8_all.deb
sudo dpkg -i ./protonvpn-stable-release_1.0.8_all.deb
sudo apt update
sudo apt install -y proton-vpn-cli
protonvpn --help
```
