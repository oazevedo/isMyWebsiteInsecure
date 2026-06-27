
***How to use GitHub Copilot CLI AI to check for website vulnerabilities.***  
<br/>

**Install GitHub Copilot CLI**    
> Website: https://docs.github.com/copilot/how-tos/copilot-cli    
> Releases: https://docs.github.com/en/copilot/how-tos/copilot-cli/set-up-copilot-cli/install-copilot-cli  

```
sudo npm install -g @github/copilot@latest
```
<br/>

**Get instructions.md**  
```
mkdir $HOME/websitesScan   # Websites assessment results folder
cd $HOME/websitesScan
rm -f instructions.md
wget https://raw.githubusercontent.com/oazevedo/isMyWebsiteInsecure/main/Linux/instructions.md 
``` 
<br/>

**Run GitHub Copilot CLI** (not run as root, need a free GitHub Account)  
```
cd $HOME/websitesScan
copilot
 > read @instructions.md
 > your target is www.aeportugal.com   # example to check for vulnerabilities on website www.aeportugal.com
```
<br/>

**Tip: run model Claude Haiku 4.5**
 ```
cd $HOME/websitesScan
copilot
 > /model claude-haiku-4.5
```
