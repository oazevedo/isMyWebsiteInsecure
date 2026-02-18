**CIBERSEGURANÇA - REQUISITOS PARA PRODUTOS, PLATAFORMAS (Websites, Portais, ....) OU SERVIÇOS DIGITAIS**  
[a incluir nos contratos com os Fornecedores de produtos digitais: plataformas, ferramentas, apps, etc.]
  
**Qualquer produto digital para o G.AEP implica a observação dos seguintes requisitos:**  
- Utilização de certificado digital em todas as páginas - que terá de se manter válido durante todo o período (obrigatório) online do produto digital;
- No caso de aquisição de registo de domínio este deve ser adquirido, com propriedade e gestão do G.AEP, por todo o período online (obrigatório);
- Utilização de bibliotecas javascript ou outros add-ins na sua versão mais recente e sem qualquer vulnerabilidade;
- Obrigatoriedade de identificar as plataformas utilizadas: sistema operativo, base de dados, web server, software de desenvolvimento, gestor de conteúdos, plug-ins instalados, etc. Sendo que só será aceite a utilização das últimas versões disponíveis dos produtos ou a imediatamente anterior estável;
- Obrigatoriedade de entregar um relatório de vulnerabilidades efetuado com a ferramenta OWASP ZAP (https://www.zaproxy.org) ou com Burp Suite Professional ( https://portswigger.net/burp/pro/), sendo que não serão aceites vulnerabilidades iguais ou superiores a risco médio;
- Obrigatoriedade de entregar um relatório de vulnerabilidades, host’s Windows ou Linux, efetuado com a ferramenta Tenable NESSUS ( https://www.tenable.com/products/nessus) ou com Greenbone OpenVAS (https://www.openvas.org/), sendo que não serão aceites vulnerabilidades iguais ou superiores a risco médio;
- Usando como referência a ferramenta de análise LIGHTHOUSE (incorporada nativamente nos browsers CHROME e EDGE) a PERFORMANCE, ACCESSIBILITY, SEO e BEST PRACTICES devem apresentar valores entre 90 e 100 (medido em todas as páginas);
- Usando a ferramenta [isMyWebsiteInsecure.bat](windows/isMyWebsiteInsecure.bat) , não deverão existir erros ou falhas de configuração/parametrização;
- Utilizando a ferramenta do Centro Nacional de Cibersegurança https://webcheck.pt validar que não existem erros;
- No cenário de existir registo/autenticação de utilizadores, é obrigatório:
	- Utilização de passwords complexas e controlo (bloqueio) após x (default = 3)  nro de tentativas falhadas
	- Base de dados dos utilizadores com passwords encriptadas (hash + salt)
	- Utilização de reCaptcha (sign-up form)
	- Autenticação multifator (um dos fatores pode ser biometria), ou
	- Autenticação via utilização de plataformas de autenticação Microsoft (Office 365) ou Google
 - No alojamento no G.AEP só é permitida a plataforma Linux/Ubuntu LTS
 
**Manutenção do produto digital durante todo o período (obrigatório) online do produto digital:** 
- No alojamento:
	- as atualizações de segurança têm de ser aplicadas automaticamente, independentemente da plataforma (Windows ou Linux); 
	- os servidores/serviços devem estar dentro do periodo de garantia dos fabricantes, ex. versão do servidor Windows que aloja deve estar dentro do suporte normal da Microsoft durante todo o periodo útil do projeto;
	- deverão estar ativos, atualizados e corretamente configurados o antivirus, firewall e WAF (Web Application Firewall);
	- deverão existir backup's online e offline c/ periodicidade diária;
	- Frameworks e plugins terão de se manter atualizados para as últimas versões disponíveis dos produtos ou as imediatamente anteriores estáveis; as atualizações de segurança devem ser aplicadas de imediato;
	- sempre que os produtos digitais forem alojados fora dos servidores do G.AEP:
		- terá de ser assegurado o acesso em contínuo e autónomo ao G.AEP para realização de auditorias de conformidade;
		- o alojamento deverá estar em Portugal (Dominios.pt ou PTisp), qualquer outra solução deverá ser na Europa e expressamente aprovada.   
	- não é permitido instalar backdoors ou qualquer outro tipo de software que pemita aceder à solução, ou obter métricas, sem conhecimento e autorização expressa.
	- pelo menos de 6 em 6 meses deverão ser efetuados novos testes que validem os "requisitos mínimos de cibersegurança".
 
 Todo o produto e alojamento digital terá de cumprir com o **RGPD**, **NIS2**, **CRA Act** e **AI Act**, se aplicável deverão ser emitidas declarações de conformidade.
 
**Notas:**  
	- deverá estar claramente definido qual é o período de vida útil do Produto Digital  
	- o pagamento dos restantes 20% está dependente da entrega e validação dos relatórios de vulnerabilidades  
	- upgrade de release ou versão implica a revalidação dos requisitos mínimos de cibersegurança

