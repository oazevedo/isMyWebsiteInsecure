**CIBERSEGURANCA - REQUISITOS PARA PRODUTOS, PLATAFORMAS (Websites, Portais, ....) OU SERVIÇOS DIGITAIS**  
[a incluir nos contratos com os Fornecedores de produtos digitais: plataformas, ferramentas, apps, etc.]
  
Qualquer produto digital para o G.AEP implica a observação dos seguintes requisitos: 
	· Utilização de certificado digital em todas as páginas - que terá de se manter válido durante todo o período (obrigatório) online do produto digital;
	· No caso de aquisição de registo de domínio este deve ser adquirido, com propriedade e gestão do G.AEP, por todo o período online (obrigatório);
	· Utilização de bibliotecas javascript ou outros add-ins na sua versão mais recente e sem qualquer vulnerabilidade;
	· Obrigatoriedade de identificar as plataformas utilizadas: sistema operativo, base de dados, web server, software de desenvolvimento, gestor de conteúdos, plug-ins instalados, etc. Sendo que só será aceite a utilização das últimas versões disponíveis dos produtos ou a imediatamente anterior estável;
	· Obrigatoriedade de entregar um relatório de vulnerabilidades efetuado com a ferramenta OWASP ZAP (https://www.zaproxy.org) ou com Burp Suite Professional ( https://portswigger.net/burp/pro/) outra equivalente, de referência no mercado, sendo que não serão aceites vulnerabilidades iguais ou superiores a risco médio;
	· Obrigatoriedade de entregar um relatório de vulnerabilidades, host’s Windows ou Linux, efetuado com a ferramenta Tenable NESSUS ( https://www.tenable.com/products/nessus) ou com Greenbone OpenVAS (https://www.openvas.org/)   outra equivalente, de referência no mercado, sendo que não serão aceites vulnerabilidades iguais ou superiores a risco médio;
	· Usando como referência a ferramenta de análise LIGHTHOUSE (incorporada nativamente nos browsers CHROME e EDGE) a PERFORMANCE, ACCESSIBILITY, SEO e BEST PRACTICES devem apresentar valores entre 90 e 100 (medido em todas as páginas);
	· Usando a ferramenta isMyWebsiteInsecure.bat, não deverão existir erros ou falhas de configuração/parametrização (new)
	· Utilizando a ferramenta do Centro Nacional de Cibersegurança https://webcheck.pt validar que não existem erros;
	· No cenário de existir registo/autenticação de utilizadores, é obrigatório:
			· Utilização de passwords complexas e controlo (bloqueio) após x (default = 3)  nro de tentativas falhadas
			· Base de dados dos utilizadores com passwords encriptadas (hash + salt)
			· Utilização de reCaptcha (sign-up form)
			· Autenticação multifator (um dos fatores pode ser biometria), ou
			· Autenticação via utilização de plataformas de autenticação Microsoft (Office 365) ou Google
 
Manutenção do produto digital durante todo o período (obrigatório) online do produto digital: 
	· No alojamento:
			· as atualizações de segurança têm de ser aplicadas automaticamente, independentemente da plataforma (Windows ou Linux); 
			· os servidores/serviços devem estar dentro do periodo de garantia dos fabricantes, ex. versão do servidor Windows que aloja deve estar dentro do suporte normal da Microsoft durante todo o periodo útil do projeto;
			· deverão estar ativos, atualizados e corretamente configurados o antivirus, firewall e WAF (Web Application Firewall);
			· deverão existir backup's online e offline c/ periodicidade diária;
	· Frameworks e plugins terão de se manter atualizados para as últimas versões disponíveis dos produtos ou as imediatamente anteriores estáveis; as atualizações de segurança devem ser aplicadas de imediato;
	· Sempre que os produtos digitais forem alojados fora dos servidores AEP, terá de ser assegurado o acesso em contínuo e autónomo à AEP, para realização de auditorias de conformidade;
	· Não é permitido instalar backdoors ou qualquer outro tipo de software que pemita aceder à solução, ou obter métricas, sem conhecimento e autorização expressa.
 
 Todo o produto digital terá de estar em conformidade com o RGPD e alinhado com as orientações da NIS2 e CRA, se aplicável deverão ser emitidas declarações de conformidade.
 
Notas:
	- deverá estar claramente definido qual é o período de vida útil do Produto Digital
	- o pagamento dos restantes 20% está dependente da entrega e validação dos relatórios de vulnerabilidades
upgrade de release ou versão implica a revalidação dos requisitos de cibersegurança![image](https://github.com/user-attachments/assets/12f2e855-cfac-47f7-8008-da2dcfd6d353)

