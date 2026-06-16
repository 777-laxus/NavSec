// =============================================================
// tela3.js  -  Remediacao: versao atual x recomendada, passos e referencia.
// =============================================================

import { getTech } from "./data.js";

function openUrl(url) {
  if (typeof chrome !== "undefined" && chrome.tabs && chrome.tabs.create) {
    chrome.tabs.create({ url });
  } else {
    window.open(url, "_blank", "noopener");
  }
}

export function init(container, ctx) {
  const tech = getTech(ctx.state.selectedTechId);

  const set = (sel, value) => {
    const el = container.querySelector(sel);
    if (el) el.textContent = value;
  };

  set("#rem-sub", `${tech.name}  -  ${tech.cveCount > 0 ? tech.cve : "sem CVE"}`);
  set("#rem-current", tech.currentVersion);
  set("#rem-recommended", tech.recommendedVersion);
  set("#rem-reference", tech.reference);

  // Passos sugeridos
  const steps = container.querySelector("#rem-steps");
  steps.innerHTML = "";
  tech.steps.forEach((step) => {
    const li = document.createElement("li");
    li.className = "steps__item";
    li.textContent = step;
    steps.appendChild(li);
  });

  // Abrir referencia oficial
  const openBtn = container.querySelector("#open-reference");
  if (openBtn) openBtn.addEventListener("click", () => openUrl(tech.reference));

  // Voltar para o detalhe
  const back = container.querySelector("#back-to-detail");
  if (back) back.addEventListener("click", () => ctx.goTo("tela2"));
}
