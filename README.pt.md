# Is My Website Insecure?
Breve resumo dos **requisitos mínimos de Cibersegurança** para o Alojamento, Desenvolvimento, Manutenção e Suporte em **todo o ciclo de vida do produto/solução**, que devem cumprir com **RGPD**, **NIS2**, **CRA - Cyber Resilience Act** e **AI Act**.  

1. **"Hardening" do Alojamento / Website / Plataforma Web**
   - alojamento dedicado ou SAS - software as a service
   - versões de software (operating system, database, content management system, frameworks, libraries, plugins, themes, etc.) mais recentes sem vulnerabilidades de segurança e "adquiridas" a entidades credíveis, ver [Library Releases](LibraryReleases.md)
   - atualizações de segurança automáticas
   - antivirus
   - firewall
   - waf - web application firewall em todas as aplicações/plataformas web
   - ssl em todas as páginas web
   - portas, abrir só as estritamente necessárias e para quem necessita
     - ex. porta 22/ssh ou 3389/rdp aberta só para os ip's públicos de quem tem que fazer a gestão da solução
     - ex. porta 443/https para o público em geral
   - logins (autenticação)
     - com controlo de tentativas falhadas
     - passwords complexas e compridas ( + 13 caracteres )
     - com 2FA duplo factor autenticação
     - implementam a sequência de autenticação: login + password complexa + reCaptcha + 2FA
   - backup's diários online e offline

2. **"Ferramentas" Cibersegurança**
   - a forma mais simples é utilizar uma VM com o [Kali Linux](https://www.kali.org) ou o [Ubuntu Desktop](https://ubuntu.com/download/desktop) e seguir os seguintes documentos:
      - como instalar: [Tools-toInstall.md](https://github.com/oazevedo/isMyWebsiteInsecure/blob/main/Linux/Tools-toInstall.md)
      - como utilizar: [HowToUse.md](https://github.com/oazevedo/isMyWebsiteInsecure/blob/main/Linux/HowToUse.md), [HowToUse-AI.md](https://github.com/oazevedo/isMyWebsiteInsecure/blob/main/Linux/HowToUse-AI.md)  
  
     | Ferramenta                                                  | Alternativa             |
     |-------------------------------------------------------------|-------------------------|
     | [isMyWebsiteInsecure-1.sh](https://github.com/oazevedo/isMyWebsiteInsecure/blob/main/Linux/isMyWebsiteInsecure-1.sh) | [isMyWebsiteInsecure.bat](https://github.com/oazevedo/isMyWebsiteInsecure/blob/main/Windows/isMyWebsiteInsecure.bat) |
     | [isMyWebsiteInsecure-2.sh](https://github.com/oazevedo/isMyWebsiteInsecure/blob/main/Linux/isMyWebsiteInsecure-2.sh) | [HowToUse-AI.md](https://github.com/oazevedo/isMyWebsiteInsecure/blob/main/Linux/HowToUse-AI.md) |
     | Browser Lighthouse                                          | [Google Page speed](https://pagespeed.web.dev/) |
     | [ZAP Proxy](https://www.zaproxy.org/)                       | [Burp suite](https://portswigger.net/burp/pro) |
     | [Tenable Nessus]( https://www.tenable.com/products/nessus ) | [Greenbone OpenVAS](https://openvas.org/) |

   **Notas:**
      - **não são aceites testes com outras ferramentas**, a não ser se expressamente autorizado.
      - [HostedScan](https://hostedscan.com) é uma ferramenta em avaliação mas que não deve ser utilizada para testes formais.  

  
4. **"Requisitos mínimos" Cibersegurança**
   - seguir o guia [DigitalProductCybersecurityRequirements.md](DigitalProductCybersecurityRequirements.md)  

5. **"Testes" Cibersegurança**
   - sugere-se a utilização do OWASP Web Security Testing Guide ( https://owasp.org/www-project-web-security-testing-guide/stable/ )
   - pretende-se que a solução/plataforma **não apresente erros ou vulnerabilidades de grau superior a "informativo".**  
   - sequência aconselhada de testes (devem ser todos executados):
      | Ferramenta                            | Descrição                                     |
      |---------------------------------------|-----------------------------------------------|
      | isMyWebsiteInsecure-1.sh \<url\>      | # testa 1ª página e alojamento                |
      | Chrome Browser > Console \<url\>      | # valida se existem erros nas páginas         |
      | Chrome Browser > Lighthouse \<url\>   | # testa página web e performance              |
      | isMyWebsiteInsecure-2.sh \<url\>      | # testa 1ª página e alojamento                |
      | ZAP \<url\>                           | # testa toda a aplicação/plataforma web       |
      | Nessus \<host\>                       | # testa todo o alojamento/aplicação           |


6. **"Relatório" Cibersegurança**
   - usar [DigitalProductCybersecurityReport.xlsx](DigitalProductCybersecurityReport.xlsx) (*) para:
      - registar configuração do alojamento, ferramentas e bibliotecas usadas no website
      - relatórios de cibersegurança
   - (*) SHA1 7f1eb3e2322fe761fba852d46d743743e3e3ed11
   

