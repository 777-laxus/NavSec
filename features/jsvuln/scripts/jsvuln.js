// =============================================================
// jsvuln.js  -  Controlador da tela "Vulnerabilidades JS" (lista).
// Contrato de view: export function init(root, ctx).
//
// Responsabilidades:
//   1) Análise estática automática da página ativa (chrome.scripting),
//      coletando achados enriquecidos (tipo de vulnerabilidade, localização
//      e PoC) e renderizando-os como itens clicáveis.
//   2) Ouvir, em tempo real, os sinks interceptados (MAIN world -> relay ->
//      chrome.runtime) e acrescentar cada alerta na lista correspondente.
//   3) Ao clicar em um achado, navegar para a rota "detail" da feature,
//      mantendo o contexto (mesmo padrão da Tela 1).
//
// Compatibilidade: os achados continuam expondo { type, severity,
// description, sample } (e os dinâmicos { sinkType, ... }) para o report.js;
// os campos novos (id, vulnClass, location, poc, cwe) são adicionais.
// =============================================================

const MESSAGE_TYPE_DYNAMIC_ALERT = "navsec:dynamic-sink-detected";
const MAX_DYNAMIC_ALERTS = 100;

// ---- Função injetada na página (ISOLATED world; serializada) ----
function staticAnalysisProbe() {
  const findings = [];
  let seq = 0;

  function cssPath(el) {
    if (!el || el.nodeType !== 1) return "";
    const parts = [];
    let node = el;
    let depth = 0;
    while (node && node.nodeType === 1 && depth < 4) {
      let part = node.tagName.toLowerCase();
      if (node.id) { parts.unshift(part + "#" + node.id); break; }
      const parent = node.parentNode;
      if (parent && parent.children) {
        const sameTag = Array.prototype.filter.call(parent.children, (c) => c.tagName === node.tagName);
        if (sameTag.length > 1) {
          part += ":nth-of-type(" + (Array.prototype.indexOf.call(sameTag, node) + 1) + ")";
        }
      }
      parts.unshift(part);
      node = parent;
      depth++;
    }
    return parts.join(" > ");
  }

  function push(o) {
    findings.push({
      id: "s" + seq++,
      type: o.type,
      severity: o.severity,
      vulnClass: o.vulnClass,
      cwe: o.cwe || null,
      description: o.description,
      sample: o.sample ? String(o.sample).slice(0, 180) : null,
      location: { path: location.pathname, selector: o.selector || null, attribute: o.attribute || null },
      poc: { description: o.pocDescription || null, snippet: o.pocSnippet || null },
    });
  }

  const inlineHandlerAttrs = ["onclick", "onerror", "onload", "onmouseover", "onmouseenter",
    "onfocus", "onblur", "onchange", "onsubmit", "oninput", "onkeydown"];
  document.querySelectorAll("*").forEach((el) => {
    inlineHandlerAttrs.forEach((attr) => {
      if (el.hasAttribute(attr)) {
        const tag = el.tagName.toLowerCase();
        push({
          type: "inline-event-handler", severity: "media",
          vulnClass: "XSS (handler inline)", cwe: "CWE-79",
          description: `Atributo "${attr}" inline encontrado em <${tag}>.`,
          sample: el.getAttribute(attr), selector: cssPath(el), attribute: attr,
          pocDescription: "Conteúdo controlado pelo atacante neste atributo seria executado como JavaScript no contexto da página.",
          pocSnippet: `<${tag} ${attr}="alert(document.cookie)">`,
        });
      }
    });
  });

  document.querySelectorAll('a[href^="javascript:"]').forEach((el) => {
    push({
      type: "javascript-href", severity: "alta",
      vulnClass: "XSS (esquema javascript:)", cwe: "CWE-79",
      description: "Link com esquema javascript: detectado.",
      sample: el.getAttribute("href"), selector: cssPath(el), attribute: "href",
      pocDescription: "Acionar o link executa o JavaScript que vem após \"javascript:\".",
      pocSnippet: el.getAttribute("href"),
    });
  });

  const cspMeta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
  document.querySelectorAll("script:not([src])").forEach((el) => {
    if (cspMeta && !el.hasAttribute("nonce")) {
      push({
        type: "inline-script-sem-nonce", severity: "baixa",
        vulnClass: "CSP — script inline sem nonce", cwe: "CWE-693",
        description: "Script inline presente em página com CSP, porém sem atributo nonce.",
        sample: null, selector: cssPath(el),
        pocDescription: "Com a CSP atual, um script inline sem nonce pode indicar política frágil ou possibilidade de bypass.",
        pocSnippet: null,
      });
    }
  });

  document.querySelectorAll("form").forEach((form) => {
    const hasHiddenToken = !!form.querySelector(
      'input[type="hidden"][name*="csrf" i], input[type="hidden"][name*="token" i]'
    );
    if (form.method && form.method.toLowerCase() === "post" && !hasHiddenToken) {
      push({
        type: "form-sem-token-aparente", severity: "baixa",
        vulnClass: "CSRF (possível)", cwe: "CWE-352",
        description: "Formulário POST sem campo oculto de token aparente (heurística, pode haver falso positivo).",
        sample: form.action || null, selector: cssPath(form), attribute: "action",
        pocDescription: "Sem token anti-CSRF, uma página externa poderia forjar este POST em nome de um usuário autenticado.",
        pocSnippet: `<form method="POST" action="${form.action || "/endpoint"}"> ...campos... </form>`,
      });
    }
  });

  document.querySelectorAll("iframe").forEach((frame) => {
    if (!frame.hasAttribute("sandbox")) {
      push({
        type: "iframe-sem-sandbox", severity: "media",
        vulnClass: "Clickjacking / iframe sem sandbox", cwe: "CWE-1021",
        description: "iframe sem atributo sandbox.",
        sample: frame.getAttribute("src"), selector: cssPath(frame), attribute: "src",
        pocDescription: "Sem sandbox, o conteúdo embutido roda com mais privilégios; combinado a clickjacking, amplia o risco.",
        pocSnippet: `<iframe src="${frame.getAttribute("src") || ""}"></iframe>`,
      });
    }
  });

  return { url: location.href, timestamp: new Date().toISOString(), findings };
}

// ---- Helpers de severidade ----
const SEVERITY_CLASS = { alta: "severity--high", media: "severity--medium", baixa: "severity--low" };
function severityClass(sev) { return "severity " + (SEVERITY_CLASS[sev] || "severity--low"); }

// ---- Renderização (DOM seguro: textContent para dados não confiáveis) ----
function buildFindingItem(finding, kind, onClick) {
  const li = document.createElement("li");
  li.className = "finding-item finding-item--clickable" + (kind === "dynamic" ? " finding-item--dynamic" : "");
  li.dataset.findingId = finding.id;
  li.setAttribute("role", "button");
  li.tabIndex = 0;

  const head = document.createElement("div");
  head.className = "finding-item__head";
  const sev = document.createElement("span");
  sev.className = severityClass(finding.severity);
  sev.textContent = finding.severity;
  const type = document.createElement("span");
  type.className = "finding-item__type";
  type.textContent = finding.vulnClass || finding.type || finding.sinkType || "achado";
  head.append(sev, type);
  if (kind === "dynamic" && finding.time) {
    const time = document.createElement("time");
    time.className = "finding-item__time";
    time.textContent = finding.time;
    head.appendChild(time);
  }

  const desc = document.createElement("p");
  desc.className = "finding-item__desc";
  desc.textContent = finding.description || "";

  const foot = document.createElement("span");
  foot.className = "finding-item__more";
  foot.textContent = "ver detalhes \u203A";

  li.append(head, desc, foot);
  li.addEventListener("click", () => onClick(finding.id));
  li.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onClick(finding.id); } });
  return li;
}

async function getActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.id) throw new Error("Não foi possível identificar a aba ativa.");
  return tab;
}
function isInjectableUrl(url) {
  if (!url) return false;
  return /^https?:\/\//i.test(url) || /^file:\/\//i.test(url);
}

// =============================================================
// init(root, ctx)
// =============================================================
export function init(root, ctx) {
  const startBtn = root.querySelector("#start-scan-btn");
  const statusEl = root.querySelector("#scan-status");
  const staticBlock = root.querySelector("#static-block");
  const staticResultsEl = root.querySelector("#static-results");
  const dynamicBlock = root.querySelector("#dynamic-block");
  const dynamicResultsEl = root.querySelector("#dynamic-results");

  let isScanning = false;

  function setStatus(text, kind) {
    statusEl.textContent = text || "";
    statusEl.dataset.kind = kind || "";
  }

  function openDetail(findingId) {
    ctx.router.navigate("detail", { findingId });
  }

  function renderStaticResults(payload) {
    staticResultsEl.innerHTML = "";
    const findings = payload.findings || [];
    if (!findings.length) {
      const p = document.createElement("p");
      p.className = "empty-state empty-state--ok";
      p.textContent = "\u2705 Nenhuma vulnerabilidade evidente foi encontrada na análise estática desta página.";
      staticResultsEl.appendChild(p);
      return;
    }
    const ul = document.createElement("ul");
    ul.className = "result-list";
    findings.forEach((f) => ul.appendChild(buildFindingItem(f, "static", openDetail)));
    staticResultsEl.appendChild(ul);
  }

  function appendDynamicAlert(alert) {
    const empty = dynamicResultsEl.querySelector(".empty-state");
    if (empty) empty.remove();
    dynamicResultsEl.prepend(buildFindingItem(alert, "dynamic", openDetail));
    const items = dynamicResultsEl.querySelectorAll(".finding-item--dynamic");
    if (items.length > MAX_DYNAMIC_ALERTS) items[items.length - 1].remove();
  }

  async function runStaticScan() {
    if (isScanning) return;
    isScanning = true;
    startBtn.disabled = true;
    staticBlock.dataset.state = "loading";
    setStatus("Analisando página atual\u2026", "loading");

    try {
      const tab = await getActiveTab();
      if (!isInjectableUrl(tab.url)) {
        throw new Error("Esta página não permite análise (ex.: páginas internas do navegador ou da Chrome Web Store).");
      }
      const [injectionResult] = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: staticAnalysisProbe,
      });
      if (!injectionResult || !injectionResult.result) {
        throw new Error("A análise não retornou resultados.");
      }
      const payload = injectionResult.result;
      ctx.state.lastStaticScan = payload;
      renderStaticResults(payload);
      staticBlock.dataset.state = "done";

      const total = payload.findings.length;
      setStatus(
        total === 0 ? "Análise concluída: nenhum problema encontrado."
                    : `Análise concluída: ${total} ponto(s) de atenção.`,
        total === 0 ? "ok" : "warn"
      );
    } catch (err) {
      console.error("[NavSec] Falha na análise estática:", err);
      staticBlock.dataset.state = "error";
      staticResultsEl.innerHTML = "";
      const p = document.createElement("p");
      p.className = "empty-state empty-state--error";
      p.textContent = "\u26A0\uFE0F " + (err.message || "Erro desconhecido ao executar a análise.");
      staticResultsEl.appendChild(p);
      setStatus("Falha ao analisar a página.", "error");
    } finally {
      isScanning = false;
      startBtn.disabled = false;
    }
  }

  startBtn.addEventListener("click", runStaticScan);

  function normalizeDynamicMessage(message) {
    if (!message || message.type !== MESSAGE_TYPE_DYNAMIC_ALERT) return null;
    const d = message.payload || {};
    if (!Array.isArray(ctx.state.dynamicAlerts)) ctx.state.dynamicAlerts = [];
    if (typeof ctx.state._dynSeq !== "number") ctx.state._dynSeq = 0;
    return {
      id: "d" + ctx.state._dynSeq++,
      sinkType: d.sinkType || "sink-desconhecido",
      severity: d.severity || "media",
      vulnClass: d.vulnClass || d.sinkType || "Sink dinâmico",
      cwe: d.cwe || null,
      description: d.description || "Sink potencialmente perigoso interceptado em tempo de execução.",
      sample: d.sample ? String(d.sample).slice(0, 180) : null,
      location: d.location || null,
      poc: d.poc ? { description: d.poc, snippet: d.sample || null } : null,
      time: new Date().toLocaleTimeString("pt-BR"),
    };
  }

  function handleRuntimeMessage(message) {
    const alert = normalizeDynamicMessage(message);
    if (!alert) return;
    dynamicBlock.dataset.state = "active";
    appendDynamicAlert(alert);
    ctx.state.dynamicAlerts.push(alert);
  }

  if (typeof ctx.state.cleanupJsVulnView === "function") ctx.state.cleanupJsVulnView();
  chrome.runtime.onMessage.addListener(handleRuntimeMessage);
  ctx.state.cleanupJsVulnView = () => chrome.runtime.onMessage.removeListener(handleRuntimeMessage);

  if (Array.isArray(ctx.state.dynamicAlerts) && ctx.state.dynamicAlerts.length > 0) {
    dynamicBlock.dataset.state = "active";
    ctx.state.dynamicAlerts.forEach((a) => appendDynamicAlert(a));
  }

  if (ctx.state.lastStaticScan) {
    staticBlock.dataset.state = "done";
    renderStaticResults(ctx.state.lastStaticScan);
  } else {
    runStaticScan();
  }
}
