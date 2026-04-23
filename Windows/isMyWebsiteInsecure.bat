@echo off
color 1f
cls

rem modified on 2026-04-23

setlocal enableextensions enabledelayedexpansion

rem --- Defaults ---
set "browser=msedge.exe"
set "protocol=https"
set "option=0"

rem --- Get current year reliably via PowerShell (independent of regional date format) ---
for /f %%i in ('powershell -NoProfile -Command "(Get-Date).Year"') do set "current_year=%%i"


rem ============================================================
:menu
rem ============================================================
title Is my Website inSecure?
cls
echo.
echo  ===========================================================
echo.
echo    Is my Website InSecure?
echo.
echo    1. Test Website - Essential tools
echo    2. Test Website - All tools
echo.
echo    3. Choose browser
echo    4. Choose protocol
echo.
echo    L. Legal and Privacy Terms
echo    X. Exit
echo.
echo    IMPORTANT: Only analyze websites you have permission
echo    to test. Always follow up with a full vulnerability
echo    scan (e.g. OWASP ZAP). This is a free tool.
echo.
echo    (c) !current_year! r3.1 Oscar Azevedo
echo  ===========================================================
echo.

rem --- Set browser private mode flag ---
set "private="
if /i "%browser%"=="brave.exe"   set "private=incognito"
if /i "%browser%"=="chrome.exe"  set "private=incognito"
if /i "%browser%"=="msedge.exe"  set "private=private"
if /i "%browser%"=="firefox.exe" set "private=private-window"

echo  ======= Current Settings =========
echo  Browser  : %browser%
echo  Protocol : %protocol%
echo  ==================================
echo.

choice /c 1234LX /n /m " Choose an option (1,2,3,4,L,X): "
set "option=%ERRORLEVEL%"

if "%option%"=="1" goto :run_tools
if "%option%"=="2" goto :run_tools
if "%option%"=="3" goto :choose_browser
if "%option%"=="4" goto :choose_protocol
if "%option%"=="5" goto :legal
if "%option%"=="6" goto :end
goto :menu


rem ============================================================
:run_tools
rem ============================================================
cls
echo.

rem --- Prompt for URL ---
set "url="
set /p "url= Enter website to analyze (e.g. www.example.com): "
echo.

rem --- Validate input ---
if "!url!"=="" (
    echo  [!] No URL entered. Returning to menu.
    timeout /t 2 >nul
    goto :menu
)

rem --- Strip leading/trailing spaces (basic) ---
for /f "tokens=* delims= " %%i in ("!url!") do set "url=%%i"

rem --- Add scheme if missing ---
echo !url! | findstr /b /c:"http://" /c:"https://" >nul 2>&1
if %errorlevel% neq 0 set "url=%protocol%://!url!"

rem --- Extract scheme ---
for /f "delims=: tokens=1" %%i in ("!url!") do set "scheme=%%i"

rem --- Extract host (strip scheme and any trailing path) ---
set "host=!url!"
set "host=!host:http://=!"
set "host=!host:https://=!"
for /f "delims=/ tokens=1" %%i in ("!host!") do set "host=%%i"

rem --- Extract domain and subdomain ---
set "domain="
set "subdomain="
for /f "delims=. tokens=1,2,3,4" %%a in ("!host!") do (
    if "%%c"=="" (
        rem  host has 2 parts: domain.tld
        set "domain=%%a.%%b"
        set "subdomain="
    ) else if "%%d"=="" (
        rem  host has 3 parts: sub.domain.tld
        set "domain=%%b.%%c"
        set "subdomain=%%a"
    ) else (
        rem  host has 4+ parts: sub.sub.domain.tld
        set "domain=%%c.%%d"
        set "subdomain=%%a.%%b"
    )
)

rem --- Resolve IPv4 address ---
set "IPv4="
for /f "tokens=2 delims=[]" %%i in ('ping -4 -n 1 "!host!" 2^>nul ^| findstr /i "Pinging"') do (
    set "IPv4=%%i"
)
if "!IPv4!"=="" set "IPv4=unresolved"

rem --- Summary ---
echo  ======= Analysis Target ============================
echo   URL       : !url!
echo   Scheme    : !scheme!
echo   Host      : !host!   [!IPv4!]
echo   Subdomain : !subdomain!
echo   Domain    : !domain!
echo   Browser   : %browser%  [private mode: %private%]
echo  ====================================================
echo.
echo  Press any key to continue...
pause >nul
echo.

rem --- Verify browser is available (check PATH then common install locations) ---
set "browser_found=0"
set "browser_exe=%browser%"

rem Check PATH first
where "%browser_exe%" >nul 2>&1
if %errorlevel%==0 set "browser_found=1"

rem Check common install locations individually
rem (pipe/loop tricks break on paths with spaces like "Program Files")
if "!browser_found!"=="0" if /i "!browser_exe!"=="msedge.exe" (
    if exist "%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"  set "browser=%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"  & set "browser_found=1"
    if exist "%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"       set "browser=%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"       & set "browser_found=1"
    if exist "%LocalAppData%\Microsoft\Edge\Application\msedge.exe"       set "browser=%LocalAppData%\Microsoft\Edge\Application\msedge.exe"       & set "browser_found=1"
)
if "!browser_found!"=="0" if /i "!browser_exe!"=="chrome.exe" (
    if exist "%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe"  set "browser=%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe"  & set "browser_found=1"
    if exist "%ProgramFiles%\Google\Chrome\Application\chrome.exe"       set "browser=%ProgramFiles%\Google\Chrome\Application\chrome.exe"       & set "browser_found=1"
    if exist "%LocalAppData%\Google\Chrome\Application\chrome.exe"       set "browser=%LocalAppData%\Google\Chrome\Application\chrome.exe"       & set "browser_found=1"
)
if "!browser_found!"=="0" if /i "!browser_exe!"=="brave.exe" (
    if exist "%ProgramFiles%\BraveSoftware\Brave-Browser\Application\brave.exe"       set "browser=%ProgramFiles%\BraveSoftware\Brave-Browser\Application\brave.exe"       & set "browser_found=1"
    if exist "%ProgramFiles(x86)%\BraveSoftware\Brave-Browser\Application\brave.exe"  set "browser=%ProgramFiles(x86)%\BraveSoftware\Brave-Browser\Application\brave.exe"  & set "browser_found=1"
    if exist "%LocalAppData%\BraveSoftware\Brave-Browser\Application\brave.exe"       set "browser=%LocalAppData%\BraveSoftware\Brave-Browser\Application\brave.exe"       & set "browser_found=1"
)
if "!browser_found!"=="0" if /i "!browser_exe!"=="firefox.exe" (
    if exist "%ProgramFiles%\Mozilla Firefox\firefox.exe"         set "browser=%ProgramFiles%\Mozilla Firefox\firefox.exe"       & set "browser_found=1"
    if exist "%ProgramFiles(x86)%\Mozilla Firefox\firefox.exe"    set "browser=%ProgramFiles(x86)%\Mozilla Firefox\firefox.exe"  & set "browser_found=1"
    if exist "%LocalAppData%\Mozilla Firefox\firefox.exe"         set "browser=%LocalAppData%\Mozilla Firefox\firefox.exe"       & set "browser_found=1"
)

if "!browser_found!"=="0" (
    echo.
    echo  [!] Browser "!browser_exe!" was not found.
    echo      Checked PATH and common install locations.
    echo      Please choose a different browser.
    echo.
    timeout /t 3 >nul
    goto :choose_browser
)

echo  [OK] Browser detected: !browser!

rem ---- Open the target website first ----
start "" "!browser!" -new-window --%private% --disable-extensions "!url!"
timeout /t 2 >nul


rem ==== SECTION 1: SSL / TLS ====
echo  [+] SSL / TLS checks...
start "" "!browser!" -new-tab --%private% "https://www.ssllabs.com/ssltest/analyze.html?d=!url!&hideResults=on&latest"
timeout /t 2 >nul

start "" "!browser!" -new-tab --%private% "https://checkcybersecurity.service.ncsc.gov.uk/ip-check/form"
timeout /t 2 >nul

if "%option%"=="2" (
start "" "!browser!" -new-tab --%private% "https://checkcybersecurity.service.ncsc.gov.uk/browser-check/form"
timeout /t 2 >nul
)

rem ==== SECTION 2: HTTP Headers & CSP ====
echo  [+] HTTP headers and CSP checks...
start "" "!browser!" -new-tab --%private% "https://securityheaders.com/?followRedirects=on&hide=on&q=!url!"
timeout /t 2 >nul

start "" "!browser!" -new-tab --%private% "https://report-uri.com/"
timeout /t 2 >nul

start "" "!browser!" -new-tab --%private% "https://developer.mozilla.org/en-US/observatory/analyze?host=!host!"
timeout /t 2 >nul

if "%option%"=="2" (
start "" "!browser!" -new-tab --%private% "https://csp-evaluator.withgoogle.com/?csp=!url!"
timeout /t 2 >nul
)

rem ==== SECTION 3: DNS / WHOIS ====
echo  [+] DNS and WHOIS checks...
start "" "!browser!" -new-tab --%private% "https://hackertarget.com/whois-lookup/"
timeout /t 2 >nul

start "" "!browser!" -new-tab --%private% "https://webcheck.pt/pt/dns/loading.php?domain=!domain!"
timeout /t 2 >nul

start "" "!browser!" -new-tab --%private% "https://internet.nl/site/!host!/"
timeout /t 2 >nul

rem ==== SECTION 4: Email Security (DMARC / DKIM / SPF) ====
echo  [+] Email security checks...
start "" "!browser!" -new-tab --%private% "https://powerdmarc.com/dkim-record-lookup/"
timeout /t 2 >nul

start "" "!browser!" -new-tab --%private% "https://domain-checker.valimail.com/dmarc/!domain!"
timeout /t 2 >nul

if "%option%"=="2" (
start "" "!browser!" -new-tab --%private% "https://checkcybersecurity.service.ncsc.gov.uk/email-security-check/results?domain=!domain!"
timeout /t 2 >nul
)

if "%option%"=="2" (
start "" "!browser!" -new-tab --%private% "https://www.immuniweb.com/email/"
timeout /t 2 >nul
)

rem ==== SECTION 5: Malware & Reputation ====
echo  [+] Malware and reputation checks...
start "" "!browser!" -new-tab --%private% "https://sitecheck.sucuri.net/results/!host!"
timeout /t 2 >nul

start "" "!browser!" -new-tab --%private% "https://www.wpsec.com/"
timeout /t 2 >nul

start "" "!browser!" -new-tab --%private% "https://www.shodan.io/domain/!domain!"
timeout /t 2 >nul

start "" "!browser!" -new-tab --%private% "https://www.shodan.io/host/!IPv4!"
timeout /t 2 >nul

if "%option%"=="2" (
start "" "!browser!" -new-tab --%private% "https://haveibeenpwned.com/"
timeout /t 2 >nul
)

if "%option%"=="2" (
start "" "!browser!" -new-tab --%private% "https://www.immuniweb.com/darkweb/"
timeout /t 2 >nul
)

rem ==== SECTION 6: Vulnerability Scanning ====
echo  [+] Vulnerability scanning tools...
start "" "!browser!" -new-tab --%private% "https://pentest-tools.com/network-vulnerability-scanning/tcp-port-scanner-online-nmap/"
timeout /t 2 >nul

start "" "!browser!" -new-tab --%private% "https://pentest-tools.com/website-vulnerability-scanning/website-scanner"
timeout /t 2 >nul

start "" "!browser!" -new-tab --%private% "https://www.immuniweb.com/websec/"
timeout /t 2 >nul

start "" "!browser!" -new-tab --%private% "https://nuxtseo.com/tools/robots-txt-validator?url=!url!"
timeout /t 2 >nul

start "" "!browser!" -new-tab --%private% "https://www.zaproxy.org/"
timeout /t 2 >nul

if "%option%"=="2" (
start "" "!browser!" -new-tab --%private% "https://owasp.org/www-project-top-ten/"
timeout /t 2 >nul
)

if "%option%"=="2" (
start "" "!browser!" -new-tab --%private% "https://portswigger.net/burp/pro"
timeout /t 2 >nul
)

if "%option%"=="2" (
start "" "!browser!" -new-tab --%private% "https://www.immuniweb.com/cloud/"
timeout /t 2 >nul
)

rem ==== SECTION 7: Security Audit Tools ====
echo  [+] Security audit tools...
start "" "!browser!" -new-tab --%private% "https://www.tenable.com/products/nessus/nessus-essentials"
timeout /t 2 >nul

start "" "!browser!" -new-tab --%private% "https://snyk.io/product/snyk-code/"
timeout /t 2 >nul

if "%option%"=="2" (
start "" "!browser!" -new-tab --%private% "https://community.greenbone.net/getting-started/greenbone-community-edition-via-linux-distribution-packages/"
timeout /t 2 >nul
)

if "%option%"=="2" (
start "" "!browser!" -new-tab --%private% "https://cisofy.com/lynis/"
timeout /t 2 >nul
)

if "%option%"=="2" (
start "" "!browser!" -new-tab --%private% "https://learn.cisecurity.org/cis-cat-lite"
timeout /t 2 >nul
)

rem ==== SECTION 8: Privacy & GDPR ====
echo  [+] Privacy and GDPR checks...
start "" "!browser!" -new-tab --%private% "https://www.cookiebot.com/en/compliance-test/?domain=!host!"
timeout /t 2 >nul

if "%option%"=="2" (
start "" "!browser!" -new-tab --%private% "https://hub.sovy.com/gdpr-scan/?domain=!host!"
timeout /t 2 >nul
)

rem ==== SECTION 9: Performance & Standards ====
echo  [+] Performance and standards checks...
start "" "!browser!" -new-tab --%private% "https://developers.google.com/speed/pagespeed/insights/?url=!url!"
timeout /t 2 >nul

if "%option%"=="2" (
start "" "!browser!" -new-tab --%private% "https://gtmetrix.com/?url=!url!"
timeout /t 2 >nul
)

start "" "!browser!" -new-tab --%private% "https://validator.w3.org/nu/?showsource=no&doc=!url!/"
timeout /t 2 >nul

start "" "!browser!" -new-tab --%private% "https://jigsaw.w3.org/css-validator/validator?uri=!url!&profile=css3svg&usermedium=all&warning=1&vextwarning=&lang=en"
timeout /t 2 >nul

echo.
echo  [OK] All tabs opened. Review the results in your browser.
echo.
pause
goto :menu


rem ============================================================
:choose_browser
rem ============================================================
cls
echo.
echo  ===========================================================
echo   Choose Browser
echo  ===========================================================
echo.
echo   B. Brave
echo   C. Chrome
echo   E. Edge  (default)
echo   F. Firefox
echo   X. Cancel
echo.
choice /n /c BCEFX /m "  Enter choice: "
if "%ERRORLEVEL%"=="1" set "browser=brave.exe"
if "%ERRORLEVEL%"=="2" set "browser=chrome.exe"
if "%ERRORLEVEL%"=="3" set "browser=msedge.exe"
if "%ERRORLEVEL%"=="4" set "browser=firefox.exe"
if "%ERRORLEVEL%"=="5" goto :menu

echo.
echo  [OK] Browser set to: %browser%
timeout /t 1 >nul
goto :menu


rem ============================================================
:choose_protocol
rem ============================================================
cls
echo.
echo  ===========================================================
echo   Choose Default Protocol
echo  ===========================================================
echo.
echo   1. https  (recommended)
echo   2. http
echo   X. Cancel
echo.
choice /n /c 12X /m "  Enter choice: "
if "%ERRORLEVEL%"=="1" set "protocol=https"
if "%ERRORLEVEL%"=="2" set "protocol=http"
if "%ERRORLEVEL%"=="3" goto :menu

echo.
echo  [OK] Protocol set to: %protocol%
timeout /t 1 >nul
goto :menu


rem ============================================================
:legal
rem ============================================================
cls
echo.
echo  ===========================================================
echo   Legal and Privacy Terms
echo  ===========================================================
echo.
echo   IMPORTANT:
echo   You should ONLY use this tool to analyze websites whose
echo   owners have given you explicit permission to do so.
echo.
echo   Third-party scanners are included for convenience.
echo   This does not imply endorsement. Each scanner has its
echo   own legal and privacy terms - please review them before
echo   use.
echo.
echo   This tool is provided "as is" and does not guarantee
echo   the accuracy of any scan results.
echo.
echo   This free tool was developed by Oscar Azevedo.
echo   Suggestions welcome:
echo     oscar.azevedo@aeportugal.pt
echo     oscar.msazevedo@gmail.com
echo.
echo  ===========================================================
echo.
pause
goto :menu


rem ============================================================
:end
rem ============================================================
echo.
echo  Goodbye!
echo.

rem --- Clean up variables ---
endlocal
exit /b 0
