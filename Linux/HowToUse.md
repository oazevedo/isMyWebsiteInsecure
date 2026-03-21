
***How to use isMyWebsiteInsecure\*.sh scripts to check for vulnerabilities***  
<br/>

**Install Linux Virtual Machine**
> get and install a [Kali Linux](https://www.kali.org/get-kali/#kali-virtual-machines) or [Ubuntu desktop](https://ubuntu.com/download/desktop) VM  
> install all tools as indicated on [Tools-toInstall](Tools-toInstall.md)
<br/>

**Check for vulnerabilities**  
> quick assessment using public web tools
```
cd $HOME/tools
./isMyWebsiteInsecure-1.sh https://www.aeportugal.com   # example to check for vulnerabilities on www.aeportugal.com
```

> more detailed evaluation using free command-line tools
```
cd $HOME/tools
./isMyWebsiteInsecure-2.sh https://www.aeportugal.com   # example to check for vulnerabilities on www.aeportugal.com
```
