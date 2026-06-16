# NavSec — Extensão Chrome (Manifest V3)

Fundação modular de uma extensão de análise de segurança de páginas web.

## Como carregar (modo desenvolvedor)

1. Abra o Chrome em `chrome://extensions`.
2. Ative o **Modo do desenvolvedor** (canto superior direito).
3. Clique em **Carregar sem compactação** e selecione a pasta `navsec/`.
4. Clique no ícone da extensão para abrir o popup.

## Estrutura

```
navsec/
├── manifest.json          # MV3 + popup
├── popup.html             # Shell (header, chevrons, #content-area, rodapé)
├── popup.js               # Carregador de views, injeção de dependências e navegação circular
├── styles/
│   ├── main.css           # Design system global + componentes compartilhados
│   ├── tela1.css          # Estilos do resumo/tecnologias
│   ├── tela2.css          # Estilos do detalhe
│   └── tela3.css          # Estilos da remediação
├── views/                 # HTML injetável (sem <html>/<body>)
│   ├── tela1.html
│   ├── tela2.html
│   └── tela3.html
├── scripts/
│   ├── data.js            # Fonte única de dados (mock) — modelo de dados
│   ├── report.js          # Geração do PDF (botão "PDF")
│   ├── tela1.js           # init(container, ctx) da tela 1
│   ├── tela2.js
│   └── tela3.js
└── icons/                 # 16 / 48 / 128
```

## Como a arquitetura funciona

- `popup.js` é carregado como módulo ES (`type="module"`). Ele registra as views, e para cada uma:
  1. injeta o `<link>` do CSS específico (uma vez);
  2. faz `fetch` do HTML e injeta em `#content-area`;
  3. faz `import()` dinâmico do script da view e chama `init(container, ctx)`.
- O objeto `ctx` é a **injeção de dependências**: expõe `state` (compartilhado), `goTo(id, opts)`, `next()` e `prev()`.
- **Navegação circular**: avançar na tela 3 volta para a tela 1 (e vice-versa). Funciona pelos chevrons laterais, pelos indicadores do rodapé e pelas setas do teclado.
- Sem scripts inline nem `onclick` no HTML — compatível com a CSP do Manifest V3.

## Observação

Os dados em `scripts/data.js` são ilustrativos. A coleta real (leitura das bibliotecas da página e consulta de CVE) é o próximo passo e exige as permissões `activeTab` e `scripting`, já declaradas no `manifest.json`.
