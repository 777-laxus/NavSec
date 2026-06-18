// =============================================================
// jsvuln-detail.js  -  Detalhe de um achado de vulnerabilidade JS.
// Lê o achado (estático ou dinâmico) do estado compartilhado pelo id
// recebido em ctx.params.findingId e exibe: tipo, severidade,
// localização (path/seletor/atributo ou stack), descrição, PoC inerte,
// CWE (com link para o MITRE) e amostra. Mesmo padrão da Tela 1.
// =============================================================

import { openUrl } from "../../../utils/util.js";

const SEVERITY_CLASS = { alta: "severity--high", media: "severity--medium", baixa: "severity--low" };
const SEVERITY_LABEL = { alta: "ALTA", media: "MÉDIA", baixa: "BAIXA" };

function findById(ctx, id) {
  const statics = (ctx.state.lastStaticScan && ctx.state.lastStaticScan.findings) || [];
  const dyn = ctx.state.dynamicAlerts || [];
  return statics.find((f) => f.id === id) || dyn.find((f) => f.id === id) || null;
}

export function init(container, ctx) {
  const classEl = container.querySelector("#jd-class");
  const badgeEl = container.querySelector("#jd-badge");
  const originEl = container.querySelector("#jd-origin");
  const content = container.querySelector("#jd-content");

  const back = container.querySelector("#jd-back");
  if (back) back.addEventListener("click", () => ctx.router.back());

  const id = ctx.params && ctx.params.findingId;
  const f = findById(ctx, id);

  if (!f) {
    classEl.textContent = "Achado não encontrado";
    badgeEl.textContent = "-";
    badgeEl.className = "badge badge--pendente";
    originEl.textContent = "Volte e selecione um item da lista.";
    return;
  }

  const isDynamic = !!f.sinkType;
  classEl.textContent = f.vulnClass || f.type || f.sinkType || "Achado";
  badgeEl.textContent = SEVERITY_LABEL[f.severity] || String(f.severity || "-").toUpperCase();
  badgeEl.className = "severity " + (SEVERITY_CLASS[f.severity] || "severity--low");
  originEl.textContent = isDynamic
    ? "Origem: interceptação dinâmica" + (f.time ? " · " + f.time : "")
    : "Origem: análise estática";

  // Tipo técnico
  content.appendChild(field("Tipo (regra)", f.type || f.sinkType || "-", "mono"));

  // Descrição
  content.appendChild(field("Descrição", f.description || "Sem descrição disponível.", "multiline"));

  // Localização
  const loc = f.location || {};
  const locParts = [];
  if (loc.path) locParts.push("path: " + loc.path);
  if (loc.selector) locParts.push("seletor: " + loc.selector);
  if (loc.attribute) locParts.push("atributo: " + loc.attribute);
  if (locParts.length) {
    content.appendChild(block("Localização", codeBlock(locParts.join("\n"))));
  }
  if (loc.stack) {
    content.appendChild(block("Origem no código (stack)", codeBlock(loc.stack)));
  }

  // Como pode ser explorada (PoC)
  const poc = f.poc || {};
  if (poc.description) {
    content.appendChild(field("Como pode ser explorada", poc.description, "multiline"));
  }
  if (poc.snippet) {
    const warn = document.createElement("p");
    warn.className = "poc-note";
    warn.textContent = "Demonstração apenas ilustrativa — não é executada pela extensão.";
    content.appendChild(block("Prova de conceito (PoC)", codeBlock(poc.snippet), warn));
  }

  // Amostra capturada
  if (f.sample) {
    content.appendChild(block("Amostra capturada", codeBlock(f.sample)));
  }

  // CWE com link para o MITRE
  if (f.cwe) {
    const link = document.createElement("button");
    link.type = "button";
    link.className = "detail-link";
    link.textContent = f.cwe + " — ver no MITRE \u2197";
    const num = String(f.cwe).replace(/\D/g, "");
    link.addEventListener("click", () => openUrl("https://cwe.mitre.org/data/definitions/" + num + ".html"));
    content.appendChild(block("Classificação (CWE)", link));
  }

  // ---------- helpers (textContent: dados não confiáveis) ----------
  // Bloco empilhado: rótulo + um ou mais nós (corrige sobreposição inline).
  function block(labelText, ...nodes) {
    const wrap = document.createElement("div");
    wrap.className = "field";
    wrap.appendChild(labelEl(labelText));
    nodes.forEach((n) => wrap.appendChild(n));
    return wrap;
  }
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
  function codeBlock(text) { const c = document.createElement("code"); c.className = "finding-item__code"; c.textContent = text; return c; }
}
