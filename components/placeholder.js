// =============================================================
// placeholder.js  -  View generica "em desenvolvimento".
// Le ctx.routeData = { title, text } e preenche a tela.
// Reaproveitada pelas features ainda nao implementadas.
// =============================================================

export function init(container, ctx) {
  const data = ctx.routeData || {};
  const title = container.querySelector("#ph-title");
  const text = container.querySelector("#ph-text");
  if (title && data.title) title.textContent = data.title;
  if (text) text.textContent = data.text || "Esta funcionalidade será implementada em breve.";
}
