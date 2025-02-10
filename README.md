# isMyWebsiteInsecure
Breve resumo dos requisitos mínimos de Cibersegurança para o Alojamento, Desenvolvimento e Manutenção em **todo o ciclo de vida do produto/solução.** Nota:estes requisitos poderão ser alterados quando entrar em funcionamento a NDIS2.

1. **"Hardening" do Alojamento / Website / Plataforma Web**
   - alojamento dedicado ou SAS - software as a service
   - versões de software (operating system, database, content management system, frameworks, libraries, plugins, themes, etc.) mais recentes sem vulnerabilidades de segurança, e "adquiridas" a entidades credíveis (ver LibraryReleases.md)
   - atualizações de segurança automáticas
   - antivirus
   - firewall
   - waf web application firewall em todas as aplicações/plataformas web
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
   - a forma mais simples é utilizar uma VM com o Kali Linux ( https://www.kali.org ) e instalar as seguintes ferramentas:
      - isMyWebsiteInsecure-1.sh &nbsp;&nbsp;&nbsp; (*) SHA1 9610c10c0b18d4f85f7e1169671b46ed567403bf  
      - isMyWebsiteInsecure-2.sh &nbsp;&nbsp;&nbsp; (*) SHA1 952aac6044a587c92dd77b4a8eb961f348df590f  
      - ZAP ( https://www.zaproxy.org/ ) ou Burp Suite ( https://portswigger.net/burp/pro )
      - Nessus ( https://www.tenable.com/products/nessus ) ou Greenbone OpenVAS ( https://openvas.org/ )  
      (*) encontram-se neste repositório  

3. **"Testes" Cibersegurança**
   - não são exaustivos. **Não são aceites testes com outras ferramentas** a não ser se expressamente autorizado.
   - pretende-se que a solução/plataforma **não apresente erros ou vulnerabilidades de grau superior a "informativo".**  
   - sequência aconselhada de testes (devem ser todos executados):
      | Ferramenta                          | Descrição                                     |
      |-------------------------------------|-----------------------------------------------|
      | isMyWebsiteInsecure-1.sh \<url\>    | # testa 1º página e alojamento                |
      | isMyWebsiteInsecure-2.sh \<url\>    | # testa 1º página e alojamento                |
      | Chrome Browser > Lighthouse \<url\> | # testa página web e performance              |
      | ZAP \<url\> ou Burp Suite \<url\>   | # testa toda a aplicação/plataforma web       |
      | Nessus \<host\> or Greenbone OpenVAS \<host\> | # testa todo o alojamento/aplicação |

