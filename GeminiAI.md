**## install Gemini AI** (need a Google Account)  
 sudo apt install gemini-cli  

create a working directory, ex. /home/kali/tmp  

**## run Gemini AI** (not run as root)  
$ gemini-cli  
\> /directory add /home/kali/tmp  


## ex. run following **prompt** to test https://www.aeportugal.com    

You are performing ethical reconnaissance.  
Authorized Target: www.aeportugal.com   
**STRICT INSTRUCTIONS:**  
	- Output each command on a separate line.  
	- Use only valid, real syntax for each tool.  
	- Do not invent flags, options, or file paths.  
	- Do not search another subdomains.   
	- For WPScan, always use --stealthy, don't use api-token option.   
	- For Dalfox, always use --waf-evasion  
	- For Nikto, use by default -ssl  
  	- Use /home/kali/tmp as a working directory, /home/kali/tmp already exist.  
**TASKS:**  
	1) Run nmap to find open ports and identify running services.  
	2) Use nikto to scan the web server for known vulnerabilities, misconfigurations and outdated software.  
	3) Use nuclei to identify security issues and weaknesses.  
	4) Run wpscan to check if it's a WordPress site, and if so, identify the theme, plugins, and any associated vulnerabilities.  
	5) Use sqlmap to check for SQL injection.  
	6) Use dalfox to check for XSS.  
Summarize the findings, provide security recommendations and hardening sugestions.  
 
