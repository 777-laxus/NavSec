// =============================================================
// reputation.feature.js  -  Feature "Reputacao da Pagina" (Tela 3).
// Placeholder arquitetado. Implementacao futura usaria um servico
// services/reputation.js para consultar a reputacao do dominio.
// =============================================================

export const reputationFeature = {
  id: "reputation",
  title: "Reputacao da Pagina",
  initialRoute: "reputacao",
  routes: {
    reputacao: {
      html: "features/reputation/views/reputacao.html",
      script: "features/reputation/scripts/reputacao.js",
      css: "features/reputation/reputacao.css",
    },
  },
};