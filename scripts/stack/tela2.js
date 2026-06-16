// =============================================================
// tela2.js  -  Detalhe da vulnerabilidade da tecnologia selecionada.
// =============================================================

import { getTech, riskLabels } from "./data.js";

export function init(container, ctx) {
  const tech = getTech(ctx.state.selectedTechId);

  const set = (sel, value) => {
    const el = container.querySelector(sel);
    if (el) el.textContent = value;
  };

  set("#detail-name", tech.name);
  set("#detail-version", `Versao detectada: ${tech.version}`);
  set("#detail-cve", tech.cveCount > 0 ? tech.cve : "Nenhuma CVE conhecida");
  set("#detail-cwe", tech.cwe);
  set("#detail-cvss", tech.cvss);
  set("#detail-desc", tech.description);

  // Badge de risco
  const badge = container.querySelector("#detail-badge");
  if (badge) {
    badge.textContent = riskLabels[tech.risk];
    badge.className = `badge badge--${tech.risk}`;
  }

  // Botao "Como corrigir" desabilitado quando nao ha o que corrigir.
  const fixBtn = container.querySelector("#go-fix");
  if (fixBtn) {
    if (tech.cveCount === 0) {
      fixBtn.disabled = true;
      fixBtn.textContent = "Sem correcao necessaria";
    } else {
      fixBtn.addEventListener("click", () => ctx.goTo("tela3"));
    }
  }

  // Voltar para o resumo
  const back = container.querySelector("#back-to-summary");
  if (back) back.addEventListener("click", () => ctx.goTo("tela1"));
}
