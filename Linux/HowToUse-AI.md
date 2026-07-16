
***How to use GitHub Copilot CLI AI to check for website vulnerabilities.***  
<br/>

**Install GitHub Copilot CLI**    
> Website: https://docs.github.com/copilot/how-tos/copilot-cli    
> Releases: https://docs.github.com/en/copilot/how-tos/copilot-cli/set-up-copilot-cli/install-copilot-cli  

```
sudo npm install -g @github/copilot@latest
```
<br/>

**Get Agent Instructions**  
> Agents info: https://agents.md  
```
mkdir $HOME/websitesScan   # Websites assessment results folder
cd $HOME/websitesScan
rm -f AGENTS.md
wget https://raw.githubusercontent.com/oazevedo/isMyWebsiteInsecure/main/Linux/AGENTS.md 
``` 
<br/>

**Run GitHub Copilot CLI** ( not run as root, need a free [GitHub Account](https://github.com/features/copilot/plans) )  
```
cd $HOME/websitesScan
copilot
> your target is www.aeportugal.com   # example to check for vulnerabilities on website www.aeportugal.com
```
<br/>

**Tips**
 ```
cd $HOME/websitesScan
copilot mcp add dalfox -- dalfox mcp   # add Dalfox MCP
copilot
 > /model claude-haiku-4.5   # Models Claude Haiku 4.5, GPT-5.6 Luna or GPT-5.4 Mini offer a lower price and good performance.
 > use dalfox MCP, check www.aeportugal.com for xss vulnerabilities    # ex. of using Dalfox MCP
```
