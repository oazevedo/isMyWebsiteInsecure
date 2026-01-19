**## install Gemini AI** (need a Google Account)  
 sudo apt install gemini-cli  

create a working directory, ex. /home/kali/tmp  

**## run Gemini AI** (not run as root)  
$ gemini-cli  
\> /directory add /home/kali/tmp  


## ex. run following **prompt** to test https://new.novorumoanorte.pt  

You are performing ethical reconnaissance.  
Use https://new.novorumoanorte.pt as a legal testing target.  
**STRICT INSTRUCTIONS:**  
	- Output each command on a separate line.  
	- Use only valid, real syntax for each tool.  
	- Do not invent flags, options, or file paths.  
	- For WPScan, always use --stealthy, don't use api-token option.   
	- For Dalfox, use --timeout 20 --worker 200 --max-cpu 2  
  	- Use /home/kali/tmp as a working directory.  
**TASKS:**  
	1) Run nmap to find open ports and identify running services.  
	2) Use nikto to scan the web server for known vulnerabilities, misconfigurations and outdated software.  
	3) Run wpscan to check if it's a WordPress site, and if so, identify the theme, plugins, and any associated vulnerabilities.  
	4) Use sqlmap to check for SQL injection.  
	5) Use dalfox to check for XSS.  
Summarize the findings, provide security recommendations and hardening sugestions.  
 
