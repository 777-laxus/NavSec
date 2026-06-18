// =============================================================
// jsvuln.feature.js  -  Feature "Vulnerabilidades JS" (Tela 2).
// Navegação interna: list <-> detail (mantendo o contexto), no mesmo
// padrão da feature "stacks".
// =============================================================

export const jsvulnFeature = {
  id: "jsvuln",
  title: "Vulnerabilidades JS",
  initialRoute: "list",
  routes: {
    list: {
      html: "features/jsvuln/views/jsvuln.html",
      script: "features/jsvuln/scripts/jsvuln.js",
      css: "features/jsvuln/jsvuln.css",
    },
    detail: {
      html: "features/jsvuln/views/jsvuln-detail.html",
      script: "features/jsvuln/scripts/jsvuln-detail.js",
      css: "features/jsvuln/jsvuln.css",
    },
  },
};
