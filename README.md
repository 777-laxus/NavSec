# NavSec — Extensão Chrome (Manifest V3)

Extensão de análise de segurança de páginas web, organizada em **features**
independentes navegáveis pelos chevrons/dots do popup.

## Como carregar (modo desenvolvedor)

1. `chrome://extensions` → ative o **Modo do desenvolvedor**.
2. **Carregar sem compactação** → selecione a pasta `navsec/` (a que contém o `manifest.json`).
3. Como o manifest usa `host_permissions` (api.osv.dev), confirme o acesso quando solicitado.

## Arquitetura

```
navsec/
├── manifest.json
├── popup.html               # shell (header, chevrons, #content-area, dots)
├── popup.js                 # bootstrap: cria o router e registra as features
├── core/
│   ├── router.js            # roteador: features + sub-rotas + params + histórico
│   ├── features.js          # registro central das features (ordem = navegação)
│   └── view-loader.js       # carrega HTML/CSS/JS de uma rota (com cache)
├── components/
│   └── placeholder.(html|js|css)   # estado "em desenvolvimento" reutilizável
├── services/                # LÓGICA / DADOS (sem acoplamento com a UI)
│   ├── detector.js          # coleta de stacks no MAIN world
│   ├── fingerprints.js      # escopo fechado de detecção
│   ├── cve.js               # consulta OSV.dev + cálculo CVSS v3.1
│   └── report.js            # geração do PDF
├── features/                # UI por funcionalidade
│   ├── stacks/              # Tela 1 — Análise de Stacks (IMPLEMENTADA)
│   │   ├── stacks.feature.js
│   │   ├── views/(list|detail).html
│   │   ├── scripts/(list|detail).js
│   │   └── stacks.css
│   ├── jsvuln/              # Tela 2 — Vulnerabilidades JS (placeholder)
│   │   └── jsvuln.feature.js
│   └── reputation/          # Tela 3 — Reputação da Página (placeholder)
│       └── reputation.feature.js
├── utils/util.js
├── styles/main.css          # design system global
└── icons/
```

### Conceitos do roteador

- **Feature**: módulo de alto nível. Os chevrons/dots alternam entre features (circular).
- **Rota**: uma view dentro de uma feature (ex.: stacks → `list` / `detail`).
- **Histórico interno**: pilha por sessão; o "voltar" navega dentro da feature
  (lista ↔ detalhe) sem cruzar para outra feature.
- Cada view exporta `init(container, ctx)`. O `ctx` injeta `state` (compartilhado),
  `params`, `routeData` e o `router`.

## Estado atual

- **Tela 1 (Stacks)** — completa: coleta as bibliotecas da página (detector),
  consulta CVE/CVSS (OSV.dev) e, ao clicar numa stack disponível, abre o detalhe
  interno (CVE, CWE, CVSS, como é explorada, remediação e link para NVD/GHSA).
- **Telas 2 e 3** — registradas como placeholders ("em desenvolvimento"),
  já navegáveis, prontas para receber suas views e serviços.

## Como adicionar a Tela 2 ou 3 no futuro

1. Crie `services/<nome>.js` com a lógica.
2. Crie `features/<nome>/` com `*.feature.js`, `views/` e `scripts/`.
3. Troque a rota `soon` por rotas reais e inclua a feature em `core/features.js`.

O núcleo (`popup.js`, `router.js`) não precisa de outras alterações.

## Permissões

`activeTab` + `scripting` (coleta no MAIN world) e `host_permissions`
para `https://api.osv.dev/*` (consulta de CVE).
