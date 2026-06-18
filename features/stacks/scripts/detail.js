// =============================================================
// stacks/detail.js  -  Tela 1 (detalhe da stack).
// Mostra a CVE mais grave (CWE, CVSS, como pode ser explorada),
// a remediacao (versao corrigida + passos) e o redirecionamento
// para a pagina oficial (NVD/GHSA). Le do contexto compartilhado.
// =============================================================

import { openUrl } from "../../../utils/util.js";

const RISK_LABEL = { alto: "ALTO", medio: "MÉDIO", ok: "OK", pendente: "-" };

export function init(container, ctx) {
  const scan = ctx.state.scan;
  const stacks = (scan && scan.technologies) || [];
  const id = (ctx.params && ctx.params.stackId) || ctx.state.selectedStackId;
  ctx.state.selectedStackId = id;
  const stack = stacks.find((s) => s.id === id) || null;

  const nameEl = container.querySelector("#d-name");
  const badgeEl = container.querySelector("#d-badge");
  const versionEl = container.querySelector("#d-version");
  const content = container.querySelector("#d-content");

  const back = container.querySelector("#back");
  if (back) back.addEventListener("click", () => ctx.router.back());

  if (!stack) {
    nameEl.textContent = "Stack não encontrada";
    badgeEl.textContent = "-";
    badgeEl.className = "badge badge--pendente";
    versionEl.textContent = "Volte e selecione uma stack da lista.";
    return;
  }

  nameEl.textContent = stack.name;
  badgeEl.textContent = RISK_LABEL[stack.risk] || "-";
  badgeEl.className = "badge badge--" + (stack.risk || "pendente");
  versionEl.textContent = "Versão detectada: " + stack.version;

  // ----- Sem vulnerabilidade / versao segura -----
  if (!stack.cveCount || !stack.worst) {
    content.appendChild(field("Situação", "Nenhuma CVE conhecida"));
    const box = versionBox("good", stack.version, "seguro");
    content.appendChild(labelEl("Versão detectada"));
    content.appendChild(box);
    content.appendChild(note("Nenhuma vulnerabilidade conhecida para a versão detectada."));
    return;
  }

  const w = stack.worst;

  // ----- Vulnerabilidade (CVE mais grave) -----
  content.appendChild(field("Identificador (CVE)", w.displayId, "mono accent"));
  content.appendChild(field("Tipo de fraqueza (CWE)", w.cwe || "Não informado"));
  content.appendChild(field(
    "Severidade (CVSS v3.1)",
    w.score != null ? w.score + " - " + w.scoreLabel : (w.scoreLabel || "Não informado"),
    "score"
  ));
  content.appendChild(field("Como pode ser explorada", w.summary || trim(w.details) || "Sem descrição disponível.", "multiline"));

  // Redirecionamento para a pagina oficial.
  if (w.url) {
    const link = document.createElement("button");
    link.type = "button";
    link.className = "detail-link";
    link.textContent = "Ver página da vulnerabilidade \u2197";
    link.addEventListener("click", () => openUrl(w.url));
    content.appendChild(link);
  }

  // CVEs adicionais.
  if (stack.cveCount > 1) {
    const extra = document.createElement("div");
    extra.className = "vuln-extra";
    extra.appendChild(labelEl("Outras vulnerabilidades"));
    const chips = document.createElement("div");
    chips.className = "vuln-extra__chips";
    stack.vulns.slice(1).forEach((v) => {
      const chip = document.createElement("button");
      chip.type = "button";
      chip.className = "vuln-chip";
      chip.textContent = v.displayId;
      chip.addEventListener("click", () => openUrl(v.url));
      chips.appendChild(chip);
    });
    extra.appendChild(chips);
    content.appendChild(extra);
  }

  // ----- Remediacao -----
  const fixed = stack.fixedVersion ? stack.fixedVersion + " ou superior" : "consulte a referência";

  content.appendChild(sectionTitle("Remediação"));

  content.appendChild(labelEl("Versão atual"));
  content.appendChild(versionBox("bad", stack.version, "vulnerável"));

  const arrow = document.createElement("div");
  arrow.className = "version-arrow";
  arrow.setAttribute("aria-hidden", "true");
  arrow.innerHTML = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none"><path d="M12 5v14m0 0 6-6m-6 6-6-6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>';
  content.appendChild(arrow);

  content.appendChild(labelEl("Versão recomendada"));
  content.appendChild(versionBox("good", fixed, "seguro"));

  content.appendChild(sectionTitle("Passos sugeridos"));
  const steps = document.createElement("ol");
  steps.className = "steps";
  [
    "Atualizar " + stack.name + " para a versão " + fixed + ".",
    "Revisar trechos que usam a biblioteca com dados de fontes não confiáveis.",
    "Testar a aplicação após a atualização.",
  ].forEach((t) => {
    const li = document.createElement("li");
    li.className = "steps__item";
    li.textContent = t;
    steps.appendChild(li);
  });
  content.appendChild(steps);

  content.appendChild(labelEl("Referência"));
  const ref = document.createElement("div");
  ref.className = "reference-card";
  ref.textContent = w.url;
  content.appendChild(ref);

  const openBtn = document.createElement("button");
  openBtn.type = "button";
  openBtn.className = "btn-outline";
  openBtn.textContent = "Abrir referência oficial \u2197";
  openBtn.addEventListener("click", () => openUrl(w.url));
  content.appendChild(openBtn);

  // ---------- helpers ----------
  function field(labelText, value, mods) {
    const wrap = document.createElement("div");
    wrap.className = "field";
    wrap.appendChild(labelEl(labelText));
    const val = document.createElement("div");
    val.className = "field__value";
    if (mods) mods.split(" ").forEach((m) => val.classList.add("field__value--" + m));
    val.textContent = value;
    wrap.appendChild(val);
    return wrap;
  }
  function labelEl(text) { const s = document.createElement("span"); s.className = "field__label"; s.textContent = text; return s; }
  function sectionTitle(text) { const h = document.createElement("h2"); h.className = "section-title"; h.textContent = text; return h; }
  function note(text) { const p = document.createElement("p"); p.className = "scan-foot__note"; p.style.textAlign = "left"; p.textContent = text; return p; }
  function versionBox(kind, value, tag) {
    const box = document.createElement("div");
    box.className = "version-box version-box--" + kind;
    const v = document.createElement("span"); v.className = "version-box__value"; v.textContent = value;
    const t = document.createElement("span"); t.className = "version-box__tag"; t.textContent = tag;
    box.append(v, t);
    return box;
  }
  function trim(t) { if (!t) return ""; return t.length > 280 ? t.slice(0, 277) + "..." : t; }
}
