# isMyWebsiteInsecure
A brief overview of the **minimum Cybersecurity requirements** for Hosting, Development, Maintenance, and Support throughout the **entire product/solution lifecycle**.

1. **"Hardening" of Hosting / Website / Web Platform**
   - Dedicated hosting or SAS - software as a service
   - Latest software versions (operating system, database, content management system, frameworks, libraries, plugins, themes, etc.) without security vulnerabilities, and "acquired" from trusted sources, see [Library Releases](LibraryReleases.md)
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
   - The simplest way is to use a VM with Kali Linux (https://www.kali.org) and install the following tools:
      - [isMyWebsiteInsecure-1.sh](isMyWebsiteInsecure-1.sh) &nbsp;&nbsp;&nbsp; (*) SHA1 372a243e39f8e62310437ab6505f96690c643bc7    
      - [isMyWebsiteInsecure-2.sh](isMyWebsiteInsecure-2.sh) &nbsp;&nbsp;&nbsp; (*) SHA1 166f9d48545d1d309e0c6ee28edc2acefcb6544e  
      - ZAP (https://www.zaproxy.org/) or Burp Suite (https://portswigger.net/burp/pro)
      - Nessus (https://www.tenable.com/products/nessus) or Greenbone OpenVAS (https://openvas.org/)  
      (*) available in this repository
   - **Tests with other tools are not accepted** unless expressly authorized.

3. **Cybersecurity "Tests"**
   - It is suggested to use the OWASP Web Security Testing Guide (https://owasp.org/www-project-web-security-testing-guide/stable/)
   - The solution/platform **must not present errors or vulnerabilities higher than "informational" level.**  
   - Recommended test sequence (all must be performed):
      | Tool                               | Description                                      |
      |------------------------------------|--------------------------------------------------|
      | isMyWebsiteInsecure-1.sh \<url\>    | # tests the first page and hosting              |
      | isMyWebsiteInsecure-2.sh \<url\>    | # tests the first page and hosting              |
      | Chrome Browser > Console \<url\>    | # validates if there are errors on the pages    |
      | Chrome Browser > Lighthouse \<url\> | # tests web page and performance                |
      | ZAP \<url\> or Burp Suite \<url\>     | # tests the entire web application/platform     |
      | Nessus \<host\> or Greenbone OpenVAS \<host\> | # tests the entire hosting/application |
     
