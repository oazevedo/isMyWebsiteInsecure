
***How to use Copilot CLI AI to check for website vulnerabilities.***  
<br/>

**Install Copilot CLI**    
> Website: https://docs.github.com/copilot/how-tos/copilot-cli    
> Releases: https://docs.github.com/en/copilot/how-tos/copilot-cli/set-up-copilot-cli/install-copilot-cli  

```
sudo npm install -g @github/copilot@latest
```
<br/>

**Get GEMINI.md**  

```
mkdir $HOME/websitesScan   # Websites assessment results folder
cd $HOME/websitesScan
rm -f GEMINI.md
wget https://raw.githubusercontent.com/oazevedo/isMyWebsiteInsecure/main/Linux/GEMINI.md 
``` 
<br/>

**Run Copilot CLI AI** (not run as root, need a free GitHub Account)  
```
cd $HOME/websitesScan
copilot
 > read @GEMINI.md
 > your target is www.aeportugal.com   # example to check for vulnerabilities on website www.aeportugal.com
```
 
