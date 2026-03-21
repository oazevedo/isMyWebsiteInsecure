
***How to use Gemini AI to check for vulnerabilities***

**Install Gemini AI**    
> Website: https://github.com/google-gemini/gemini-cli  
> Releases: https://github.com/google-gemini/gemini-cli/releases  

```
sudo npm install -g @google/gemini-cli@latest  
```

**Get GEMINI.md**  

```
mkdir $HOME/Gemini   # Gemini work folder
cd $HOME/Gemini
rm -f GEMINI.md
wget https://raw.githubusercontent.com/oazevedo/isMyWebsiteInsecure/main/Linux/GEMINI.md
``` 



**Run Gemini AI** (not run as root, need a free Google Account)  
cd $HOME/Gemini  
gemini  
\> your target is www.aeportugal.com  &nbsp;&nbsp; # example to check for vulnerabilities on www.aeportugal.com

 
