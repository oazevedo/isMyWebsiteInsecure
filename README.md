# isMyWebsiteInsecure
Breve resumo dos requisitos mínimos de Cibersegurança para o Alojamento, Desenvolvimento e Manutenção em todo o ciclo de vida do produto/solução

1. "Hardening" do Alojamento / Website / Plataforma Web 
   - alojamento dedicado
   - versões de software (os, db, cms, frameworks, library, themes, etc.) mais recentes sem vulnerabilidades de segurança e "adquiridas" a entidades credíveis
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

2. Cibersegurança
  - a forma mais simples é utilizar uma vm com o Kali Linux ( https://www.kali.org ) que já tem as ferramentas pré-instaladas
  - 
