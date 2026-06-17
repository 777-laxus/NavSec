// =============================================================
// jsvuln.feature.js  -  Feature "Vulnerabilidades JS" (Tela 2).
// Placeholder arquitetado. Quando for implementada, troque a
// rota "soon" por rotas reais (ex.: list/detail) e crie a pasta
// views/ + scripts/ + um servico services/jsVulnScanner.js.
// =============================================================

export const jsvulnFeature = {
  id: "jsvuln",
  title: "Vulnerabilidades JS",
  initialRoute: "jsvuln",
  routes: {
    jsvuln: {
      html: "features/jsvuln/views/jsvuln.html",
      script: "features/jsvuln/scripts/jsvuln.js",
      css: "features/jsvuln/jsvuln.css",
    },
  },
};
