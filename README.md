# NavSec

> Diagnóstico de segurança de aplicações web direto no navegador.

NavSec é uma extensão para o Google Chrome (Manifest V3) que analisa a página
aberta na aba ativa e aponta, de forma não-intrusiva, fragilidades de segurança
do lado do cliente: bibliotecas JavaScript com vulnerabilidades conhecidas (CVE),
padrões inseguros de JavaScript/DOM e a reputação do domínio — sempre com
severidade e orientação de correção.

---

## Equipe

- **Equipe:** EMBRAZIL
- **Integrantes:** Alexandre, Atos, Bento e Vinícius

## Trilha

**Trilha 1 — AppHardener** (diagnóstico e hardening de aplicações web).

---

## Foco da ferramenta

Apoiar a **análise de segurança de aplicações web**, atuando tanto no
diagnóstico e hardening (Trilha AppHardener) quanto como **ferramenta de apoio
a pentest e reconhecimento (recon)**. Em uma passagem sobre a página atual, o
NavSec mapeia a **superfície client-side** da aplicação — bibliotecas e versões
em uso, vulnerabilidades conhecidas (CVE), padrões inseguros de JavaScript/DOM
e reputação do domínio — e entrega cada achado com severidade e orientação de
correção, sem exigir instalação de servidor ou configuração complexa.

Por rodar no próprio navegador e ser não-intrusiva na leitura, é útil para
times de desenvolvimento (hardening contínuo) e também para analistas na fase
de **levantamento/recon** de uma avaliação de segurança, agilizando a triagem
de fragilidades antes de etapas mais profundas.

---

## Descrição resumida da solução

A ferramenta é organizada em três áreas (features), navegáveis pelo popup:

1. **Análise de Stacks** — detecta as bibliotecas JavaScript presentes na página
   e suas versões, consulta vulnerabilidades conhecidas (CVE) e calcula a
   severidade (CVSS), com versão corrigida e link para a referência oficial.
2. **Vulnerabilidades JavaScript** — analisa a página em busca de padrões
   inseguros (análise estática) e observa, em tempo de execução, o uso de
   funções perigosas do DOM/JS (interceptação dinâmica de *sinks*).
3. **Reputação da Página** — avalia a reputação do domínio/IP e os cabeçalhos
   de segurança da aplicação.

Os achados podem ser exportados em um **relatório consolidado em PDF**.

---

## Funcionalidades implementadas

**Análise de Stacks**
- Detecção de bibliotecas e versões (jQuery, AngularJS, Vue.js, Lodash,
  Moment.js, Bootstrap).
- Consulta de CVE por versão via **OSV.dev**.
- Cálculo de severidade **CVSS v3.1** e classificação de risco (Alto/Médio/OK).
- Tela de detalhe com CVE, CWE, versão corrigida e redirecionamento para
  NVD/GHSA.

**Vulnerabilidades JavaScript**
- Análise estática do DOM: handlers de evento inline, links `javascript:`,
  `<script>` inline sem `nonce` (com CSP), formulários POST sem token CSRF e
  `iframe` sem `sandbox`.
- Interceptação dinâmica de *sinks*: `eval`, `Function`, `document.write`,
  `innerHTML`/`outerHTML`, `insertAdjacentHTML`, `setAttribute` e `postMessage`.
- Classificação em XSS, DOM-based XSS, Code Injection, CSRF e Clickjacking.

**Reputação da Página**
- Reputação de domínio (VirusTotal) e de IP (AbuseIPDB).
- Verificação de cabeçalhos de segurança da resposta.

**Comuns**
- Navegação entre as telas pelo popup.
- Geração de relatório em PDF dos achados.

---

## Arquitetura e módulos principais

A aplicação separa **núcleo**, **serviços** (lógica/dados) e **features** (UI),
o que facilita a manutenção e a expansão.

```
NavSec/
├── manifest.json              # Manifesto MV3, permissões e content scripts
├── popup.html                 # Shell (cabeçalho, navegação, área de conteúdo)
├── popup.js                   # Bootstrap: cria o roteador e registra as features
│
├── core/                      # Núcleo reutilizável
│   ├── router.js              # Roteamento entre features + sub-rotas + histórico
│   ├── features.js            # Registro central das features
│   └── view-loader.js         # Carregamento de HTML/CSS/JS por rota (com cache)
│
├── services/                  # Lógica e dados (sem acoplamento com a UI)
│   ├── detector.js            # Coleta de stacks no contexto da página (MAIN world)
│   ├── fingerprints.js        # Escopo/fingerprints das bibliotecas detectadas
│   ├── cve.js                 # Consulta OSV.dev + cálculo CVSS v3.1
│   └── report.js              # Geração do relatório em PDF
│
├── features/                  # Interface por funcionalidade
│   ├── stacks/                # Tela 1 — Análise de Stacks
│   ├── jsvuln/                # Tela 2 — Vulnerabilidades JavaScript
│   │   └── scripts/           #   inclui sink-interceptor (MAIN) e sink-relay
│   └── reputation/            # Tela 3 — Reputação da Página
│
├── components/                # Componentes reutilizáveis (placeholder)
├── utils/                     # Utilitários (ex.: abertura de links)
├── styles/                    # Estilos globais e de telas
└── icons/                     # Ícones da extensão (16/48/128)
```

**Como a interface é montada:** o `popup.js` cria o roteador (`core/router.js`)
e registra as features (`core/features.js`). Cada feature declara suas rotas
(views), carregadas sob demanda pelo `core/view-loader.js`. As telas consomem os
serviços em `services/` para obter os dados (detecção, CVE, relatório).

---

## Fluxo principal de uso

1. O usuário abre o popup do NavSec na aba que deseja analisar.
2. **Análise:** a extensão injeta uma rotina no contexto da página
   (`world: MAIN`) e lê stacks, padrões de DOM/JS e cabeçalhos.
3. **Identificação:** aponta bibliotecas e padrões/*sinks* potencialmente
   inseguros.
4. **Classificação:** consulta CVE (OSV.dev), calcula CVSS v3.1, associa CWE e
   define a severidade.
5. **Remediação:** apresenta a versão corrigida e redireciona para a referência
   oficial (NVD/GHSA).
6. **Relatório:** os achados podem ser exportados em PDF.

---

## Tecnologias utilizadas

**Stack**
- Extensão Chrome — **Manifest V3**
- **JavaScript puro** (ES Modules), HTML e CSS
- Execução 100% local no navegador, sem etapa de *build* e sem dependências
  externas de empacotamento

**APIs externas**
- **OSV.dev** — vulnerabilidades (CVE) por versão de pacote
- **VirusTotal** — reputação de domínio
- **AbuseIPDB** — reputação de IP
- **Google DNS** — resolução de domínio

**APIs do navegador**
- `chrome.scripting` (`executeScript`, `world: MAIN`)
- `content_scripts` (`run_at: document_start`) para a interceptação dinâmica
- `chrome.tabs` e `chrome.runtime` (mensageria interna)

---

## Instruções básicas de execução

1. Clone ou baixe o repositório.
2. No Chrome, acesse `chrome://extensions`.
3. Ative o **Modo do desenvolvedor** (canto superior direito).
4. Clique em **Carregar sem compactação** e selecione a pasta do projeto
   (a que contém o `manifest.json`).
5. Ao carregar, confirme as permissões de acesso às APIs externas
   (`host_permissions`).
6. Abra um site (`http`/`https`), clique no ícone do NavSec e utilize as telas.

**Observações**
- Após (re)carregar a extensão, **recarregue a aba** alvo, pois a interceptação
  dinâmica é injetada no carregamento da página.
- Para analisar arquivos locais (`file://`), ative em
  `chrome://extensions` → NavSec → **Detalhes** → *Permitir acesso a URLs de arquivo*.

---

## Limitações atuais

- **Escopo client-side:** o NavSec analisa o que a página expõe ao navegador;
  não avalia autenticação/autorização ou regras do back-end.
- **Interceptação dinâmica:** os *sinks* só são registrados com o popup aberto,
  pois ainda não há um *service worker* para armazenar os eventos.
- **Reputação (Tela 3):** depende de chaves de API válidas (VirusTotal/AbuseIPDB)
  e de um domínio público; não é aplicável a `localhost`. Recomenda-se manter as
  chaves **fora do versionamento** (configuração do usuário/ambiente).
- **Apoio à análise, não exploração ativa:** o NavSec cobre a fase de
  análise/reconhecimento (fingerprinting, achados client-side, reputação); a
  exploração ativa, o *crawling* e os testes de back-end permanecem a cargo do
  analista e de ferramentas dedicadas.

---

## Possibilidades de evolução futura

- *Service worker* para registrar os *sinks* dinâmicos sem depender do popup
  aberto.
- Mover as chaves de API para configuração (ex.: `chrome.storage`) e remover
  segredos do código-fonte.
- Ampliar o catálogo de bibliotecas detectadas e o cache das consultas de CVE.
- Incluir um **checklist de controles** (autenticação, autorização, *headers*)
  para cobrir mais itens do AppHardener.
- Enriquecer o relatório em PDF (CWE, PoC, referências por achado).

---

## Repositório

https://github.com/AtosOmena/NavSec
