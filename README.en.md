# Is My Website Insecure?
A brief overview of the **minimum Cybersecurity requirements** for Hosting, Development, Maintenance, and Support throughout the **entire product/solution lifecycle**, wich must comply with the **NDIS2** and **CRA - Cyber Resilience Act**.  

1. **"Hardening" of Hosting / Website / Web Platform**
   - Dedicated hosting or SaaS (Software as a Service)
   - Ensure all software (operating system, database, CMS, frameworks, libraries, plugins, themes, etc.) is up-to-date, free from security vulnerabilities and obtained from trusted sources. See [Library Releases](LibraryReleases.md)
   - Automatic security updates
   - Antivirus
   - Firewall
   - WAF - web application firewall on all web applications/platforms
   - SSL on all web pages
   - Ports: open only those strictly necessary and for those who need access
     - ex. port 22/ssh or 3389/rdp open only to the public IPs of those managing the solution
     - ex. port 443/https for the general public
   - Logins (authentication)
     - with failed attempt control
     - complex and long passwords ( +13 characters )
     - with 2FA two-factor authentication
     - implement the authentication sequence: login + complex password + reCaptcha + 2FA
   - Daily backups online and offline

2. **Cybersecurity "Tools"**
   - The simplest approach is to use a virtual machine (VM) with Kali Linux (https://www.kali.org) and install the following tools:
      - [isMyWebsiteInsecure-1.sh](isMyWebsiteInsecure-1.sh) &nbsp;&nbsp;&nbsp; (*) SHA1 8c2ae9250d5f5f91837b770e0174f17a50737f14    
      - [isMyWebsiteInsecure-2.sh](isMyWebsiteInsecure-2.sh) &nbsp;&nbsp;&nbsp; (*) SHA1 c36c75f582b6681bd82e0b7ef46ad078686fd273  
      - [Gemini AI](GeminiAI.md)   
      - ZAP (https://www.zaproxy.org/) or Burp Suite (https://portswigger.net/burp/pro)
      - Nessus (https://www.tenable.com/products/nessus) or Greenbone OpenVAS (https://openvas.org/)  
      (*) available in this repository
   - Do not use tools other than the ones listed unless explicitly authorized.

3. **Cybersecurity "minimum Requirements"**
   - Refer to the document [DigitalProductCybersecurityRequirements.md](DigitalProductCybersecurityRequirements.md)  

4. **Cybersecurity "Tests"**
   - It is suggested to use the OWASP Web Security Testing Guide (https://owasp.org/www-project-web-security-testing-guide/stable/)
   - The solution/platform **must not present errors or vulnerabilities higher than "informational" level.**  
   - Recommended test sequence (all must be performed):
      | Tool                               | Description                                      |
      |------------------------------------|--------------------------------------------------|
      | isMyWebsiteInsecure-1.sh \<url\> (*)   | # tests the first page and hosting           |
      | Chrome Browser > Console \<url\>    | # validates if there are errors on the pages    |
      | Chrome Browser > Lighthouse \<url\> | # tests web page and performance                |
      | isMyWebsiteInsecure-2.sh \<url\>    | # tests the first page and hosting              |
      | Gemini AI                           | # Gemini AI cybersecurity analysis (optional)   |
      | ZAP \<url\> or Burp Suite \<url\>   | # tests the entire web application/platform     |
      | Nessus \<host\> or Greenbone OpenVAS \<host\> | # tests the entire hosting/application |

       (*) or isMyWebsiteInsecure.bat

5. **Cybersecurity "Reporting"**
   - Use [DigitalProductCybersecurityReport.xlsx](DigitalProductCybersecurityReport.xlsx) (*) to:   
        - document hosting configurations, tools and libraries used on the website
        - cybersecurity test reports
   - (*) SHA1 7f1eb3e2322fe761fba852d46d743743e3e3ed11

