Note: tested only on Kali linux  

***How to use AI to check for vulnerabilities***

**Create working directory**  
mkdir $HOME/Gemini  

**Get GEMINI.md**  
Copy, from this repository, [GEMINI.md](GEMINI.md) to $HOME/Gemini  

**Install Gemini AI** (need a Google Account)  
https://github.com/google-gemini/gemini-cli  
sudo npm install -g @google/gemini-cli@latest  

**Run Gemini AI** (not run as root)  
cd $HOME/Gemini  
gemini  
\> your target is www.aeportugal.com  &nbsp;&nbsp; # example to check for vulnerabilities on www.aeportugal.com

 
