// =============================================================
// stacks/list.js  -  Tela 1 (lista).
// Fase 1: coleta as stacks da pagina (services/detector).
// Fase 2: consulta as CVE de cada versao (services/cve / OSV.dev).
// Ao clicar numa stack disponivel, navega para a rota "detail"
// mantendo o contexto (router.navigate).
// =============================================================

import { detectTechnologies } from "../../../services/detector.js";
import { queryAll } from "../../../services/cve.js";

const VIA_LABEL = {
  runtime: "via objeto global",
  src: "via arquivo .js",
  global: "via objeto global",
};
const RISK_LABEL = { alto: "ALTO", medio: "MEDIO", ok: "OK", pendente: "-" };

export function init(container, ctx) {
  const urlInput = container.querySelector("#page-url");
  const body = container.querySelector("#scan-body");

  const setUrl = (v) => { if (urlInput) urlInput.value = v || "-"; };
  const loading = (msg) => {
    body.innerHTML =
      '<div class="scan-loading"><span class="spinner" aria-hidden="true"></span>' +
      "<span>" + msg + "</span></div>";
  };

  // ---------- render ----------
  function render(scan) {
    ctx.state.scan = scan;
    if (scan.status !== "ok") { setUrl(scan.url || "-"); renderState(scan); return; }
    setUrl(scan.url);
    const stacks = scan.technologies || [];
    if (!stacks.length) { renderEmpty(); return; }
    renderResults(scan, stacks);
  }

  function renderResults(scan, stacks) {
    body.innerHTML = "";

    const counts = { alto: 0, medio: 0, ok: 0 };
    stacks.forEach((s) => { if (counts[s.risk] != null) counts[s.risk]++; });

    body.appendChild(sectionTitle("Resumo"));
    const grid = document.createElement("div");
    grid.className = "summary-grid";
    grid.appendChild(summaryCard("alto", counts.alto, "Alto"));
    grid.appendChild(summaryCard("medio", counts.medio, "Medio"));
    grid.appendChild(summaryCard("ok", counts.ok, "OK"));
    body.appendChild(grid);

    body.appendChild(sectionTitle("Stacks detectadas"));
    const list = document.createElement("div");
    list.className = "tech-list";
    stacks.forEach((stack) => list.appendChild(stackCard(stack)));
    body.appendChild(list);

    if (scan.cveStatus === "partial") {
      const warn = document.createElement("p");
      warn.className = "scan-foot__note";
      warn.textContent = "Nao foi possivel consultar a CVE de alguns itens (verifique a conexao).";
      body.appendChild(warn);
    }
    body.appendChild(scanFoot());
  }

  // Valores vindos da pagina sao tratados como nao confiaveis: textContent.
  function stackCard(stack) {
    const available = stack.status === "ok"; // disponivel para abrir o detalhe
    const card = document.createElement(available ? "button" : "div");
    card.className = "tech-card" + (available ? "" : " tech-card--disabled");
    if (available) card.type = "button";

    const main = document.createElement("span");
    main.className = "tech-card__main";
    main.appendChild(span("tech-card__name", stack.name));
    main.appendChild(span("tech-card__version", "versao " + stack.version));
    main.appendChild(span("tech-card__via", VIA_LABEL[stack.via] || "detectada"));

    const meta = document.createElement("span");
    meta.className = "tech-card__meta";
    const badge = document.createElement("span");
    badge.className = "badge badge--" + stack.risk;
    badge.textContent = RISK_LABEL[stack.risk] || "-";
    meta.appendChild(badge);
    meta.appendChild(span("tech-card__cve", cveLabel(stack)));

    const chev = span("tech-card__chevron", available ? "\u203A" : "");
    chev.setAttribute("aria-hidden", "true");

    card.append(main, meta, chev);
    if (available) {
      card.addEventListener("click", () =>
        ctx.router.navigate("detail", { stackId: stack.id })
      );
    }
    return card;
  }

  function cveLabel(stack) {
    if (stack.status === "error") return "CVE: indisponivel";
    if (stack.status === "skipped") return "versao desconhecida";
    return stack.cveCount + (stack.cveCount === 1 ? " CVE" : " CVEs");
  }

  function summaryCard(variant, num, label) {
    const card = document.createElement("div");
    card.className = "summary-card summary-card--" + variant;
    card.appendChild(span("summary-card__num", String(num)));
    card.appendChild(span("summary-card__label", label));
    return card;
  }

  function renderEmpty() {
    body.innerHTML = "";
    const msg = document.createElement("div");
    msg.className = "state-message";
    msg.appendChild(strong("Nenhuma stack conhecida encontrada"));
    msg.appendChild(span("", "A pagina nao usa (ou nao expoe) as bibliotecas do escopo atual."));
    body.appendChild(msg);
    body.appendChild(scanFoot());
  }

  function renderState(scan) {
    body.innerHTML = "";
    const map = {
      restricted: ["Pagina nao analisavel", "Esta e uma pagina interna do navegador. Abra um site (http/https) e tente novamente."],
      "no-tab": ["Nenhuma aba ativa", "Nao foi possivel identificar a aba atual."],
      unsupported: ["Recurso indisponivel", "Abra a extensao a partir de uma aba normal do navegador."],
      error: ["Falha na analise", scan.message || "Ocorreu um erro inesperado."],
    };
    const [title, text] = map[scan.status] || map.error;
    const msg = document.createElement("div");
    msg.className = "state-message";
    msg.appendChild(strong(title));
    msg.appendChild(span("", text));
    body.appendChild(msg);
    body.appendChild(scanFoot());
  }

  function scanFoot() {
    const foot = document.createElement("div");
    foot.className = "scan-foot";
    foot.appendChild(noteSpan("Fonte das CVEs: OSV.dev"));
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "btn-ghost";
    btn.textContent = "Analisar novamente";
    btn.addEventListener("click", runScan);
    foot.appendChild(btn);
    return foot;
  }

  // ---------- helpers de DOM ----------
  function span(cls, text) { const e = document.createElement("span"); if (cls) e.className = cls; e.textContent = text; return e; }
  function noteSpan(text) { return span("scan-foot__note", text); }
  function strong(text) { const e = document.createElement("strong"); e.textContent = text; return e; }
  function sectionTitle(text) { const h = document.createElement("h2"); h.className = "section-title"; h.textContent = text; return h; }

  // ---------- fluxo ----------
  async function runScan() {
    setUrl("analisando...");
    loading("Analisando a pagina...");

    let scan;
    try {
      scan = await detectTechnologies();
    } catch (e) {
      render({ status: "error", message: String(e) });
      return;
    }
    if (scan.status !== "ok") { render(scan); return; }

    setUrl(scan.url);
    if (scan.technologies.length) {
      loading("Consultando CVEs (OSV.dev)...");
      try {
        const enriched = await queryAll(scan.technologies);
        scan.technologies = enriched;
        scan.cveStatus = enriched.some((t) => t.status === "error") ? "partial" : "ok";
      } catch (e) {
        scan.technologies = scan.technologies.map((t) => ({ ...t, status: "error", risk: "pendente", cveCount: 0 }));
        scan.cveStatus = "partial";
      }
    }
    render(scan);
  }

  // Reaproveita a analise da sessao (nao reescaneia ao voltar do detalhe).
  if (ctx.state.scan) render(ctx.state.scan);
  else runScan();
}
