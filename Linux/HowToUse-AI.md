
***How to use Gemini AI to check for website vulnerabilities.***  
<br/>

**Install Gemini AI**    
> Website: https://github.com/google-gemini/gemini-cli  
> Releases: https://github.com/google-gemini/gemini-cli/releases  

```
sudo npm install -g @google/gemini-cli@latest  
```
<br/>

**Get GEMINI.md**  

```
mkdir $HOME/Gemini   # Gemini folder
mkdir $HOME/websitesScan   # assessment results folder
cd $HOME/Gemini
rm -f GEMINI.md
wget https://raw.githubusercontent.com/oazevedo/isMyWebsiteInsecure/main/Linux/GEMINI.md  
``` 
<br/>

**Run Gemini AI** (not run as root, need a free Google Account)  
```
cd $HOME/Gemini  
gemini  
 > your target is www.aeportugal.com   # example to check for vulnerabilities on website www.aeportugal.com
```
 
