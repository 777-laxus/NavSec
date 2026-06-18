// =============================================================
// stacks.feature.js  -  Feature "Analise de Stacks" (Tela 1).
// Define o titulo, a rota inicial e o mapa de rotas (views).
// Navegacao interna: list <-> detail (mantendo o contexto).
// =============================================================

export const stacksFeature = {
  id: "stacks",
  title: "Análise de Stacks",
  initialRoute: "list",
  routes: {
    list: {
      html: "features/stacks/views/list.html",
      script: "features/stacks/scripts/list.js",
      css: "features/stacks/stacks.css",
    },
    detail: {
      html: "features/stacks/views/detail.html",
      script: "features/stacks/scripts/detail.js",
      css: "features/stacks/stacks.css",
    },
  },
};
