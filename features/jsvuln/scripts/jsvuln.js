// =============================================================
// vulnerabilidades.js  -  Controlador da tela "Vulnerabilidades encontradas".
// Segue o contrato de modulo de view usado pelo shell (popup.js):
//   export function init(root, ctx) { ... }
//
// Responsabilidades desta tela:
//   1) Disparar a Analise Estatica AUTOMATICAMENTE ao abrir esta tela
//      (chrome.scripting.executeScript na aba ativa) e renderizar os
//      achados, sem exigir interacao do usuario. O botao "Analisar Pagina
//      Atual" continua disponivel para permitir uma nova analise manual
//      (ex.: apos a pagina mudar de estado).
//   2) Ouvir mensagens da Interceptacao Dinamica de sinks (que roda no MAIN
//      world, injetada via content_scripts em document_start) e acrescentar
//      cada alerta em tempo real na lista correspondente.
//
// Observacao de arquitetura: scripts no MAIN world nao tem acesso ao objeto
// chrome.*, entao a interceptacao dinamica so chega aqui se houver um
// "relay" no ISOLATED world (outro content script, sem "world": "MAIN")
// que reenvie o evento via chrome.runtime.sendMessage. Este modulo assume
// que esse relay existe e envia mensagens no formato descrito em
// `normalizeDynamicMessage`.
// =============================================================

const MESSAGE_TYPE_DYNAMIC_ALERT = "navsec:dynamic-sink-detected";
const MAX_DYNAMIC_ALERTS = 100;

// ---- Funcao injetada na pagina (roda isolada, dentro do contexto da aba) ----
// Mantida como function declarada para ser serializada pelo executeScript.
// Nao deve depender de nenhuma variavel externa do popup.
function staticAnalysisProbe() {
  const findings = [];

  function pushFinding(type, severity, description, sample) {
    findings.push({
      type,
      severity, // "alta" | "media" | "baixa"
      description,
      sample: sample ? String(sample).slice(0, 180) : null,
    });
  }

  // 1) Atributos de evento inline (potencial XSS / handlers expostos no DOM)
  const inlineHandlerAttrs = [
    "onclick", "onerror", "onload", "onmouseover", "onmouseenter",
    "onfocus", "onblur", "onchange", "onsubmit", "oninput", "onkeydown",
  ];
  document.querySelectorAll("*").forEach((el) => {
    inlineHandlerAttrs.forEach((attr) => {
      if (el.hasAttribute(attr)) {
        pushFinding(
          "inline-event-handler",
          "media",
          `Atributo "${attr}" inline encontrado em <${el.tagName.toLowerCase()}>`,
          el.getAttribute(attr)
        );
      }
    });
  });

  // 2) href="javascript:" (vetor classico de XSS)
  document.querySelectorAll('a[href^="javascript:"]').forEach((el) => {
    pushFinding(
      "javascript-href",
      "alta",
      "Link com esquema javascript: detectado",
      el.getAttribute("href")
    );
  });

  // 3) <script> inline sem nonce/integrity em pagina com CSP declarada
  const cspMeta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
  document.querySelectorAll("script:not([src])").forEach((el) => {
    if (cspMeta && !el.hasAttribute("nonce")) {
      pushFinding(
        "inline-script-sem-nonce",
        "baixa",
        "Script inline presente em pagina com CSP, porem sem atributo nonce",
        null
      );
    }
  });

  // 4) Formularios sem atributo de protecao CSRF visivel (heuristica simples)
  document.querySelectorAll("form").forEach((form) => {
    const hasHiddenToken = !!form.querySelector(
      'input[type="hidden"][name*="csrf" i], input[type="hidden"][name*="token" i]'
    );
    if (form.method && form.method.toLowerCase() === "post" && !hasHiddenToken) {
      pushFinding(
        "form-sem-token-aparente",
        "baixa",
        "Formulario POST sem campo oculto de token aparente (heuristica, pode haver falso positivo)",
        form.action || null
      );
    }
  });

  // 5) iframes sem sandbox
  document.querySelectorAll("iframe").forEach((frame) => {
    if (!frame.hasAttribute("sandbox")) {
      pushFinding(
        "iframe-sem-sandbox",
        "media",
        "iframe sem atributo sandbox",
        frame.getAttribute("src")
      );
    }
  });

  return {
    url: location.href,
    timestamp: new Date().toISOString(),
    findings,
  };
}

// ---- Helpers de renderizacao ----

function severityBadgeClass(severity) {
  if (severity === "alta") return "severity severity--high";
  if (severity === "media") return "severity severity--medium";
  return "severity severity--low";
}

function escapeHtml(value) {
  const div = document.createElement("div");
  div.textContent = value == null ? "" : String(value);
  return div.innerHTML;
}

function renderStaticResults(container, payload) {
  const { findings } = payload;

  if (!findings || findings.length === 0) {
    container.innerHTML = `
      <p class="empty-state empty-state--ok">
        ✅ Nenhuma vulnerabilidade evidente foi encontrada na analise estatica desta pagina.
      </p>`;
    return;
  }

  const items = findings
    .map((f) => {
      return `
        <li class="finding-item">
          <div class="finding-item__head">
            <span class="${severityBadgeClass(f.severity)}">${escapeHtml(f.severity)}</span>
            <span class="finding-item__type">${escapeHtml(f.type)}</span>
          </div>
          <p class="finding-item__desc">${escapeHtml(f.description)}</p>
          ${f.sample ? `<code class="finding-item__sample">${escapeHtml(f.sample)}</code>` : ""}
        </li>`;
    })
    .join("");

  container.innerHTML = `<ul class="result-list">${items}</ul>`;
}

function appendDynamicAlert(listEl, alert) {
  // Remove o estado vazio na primeira mensagem real.
  const emptyState = listEl.querySelector(".empty-state");
  if (emptyState) emptyState.remove();

  const li = document.createElement("li");
  li.className = "finding-item finding-item--dynamic";
  li.innerHTML = `
    <div class="finding-item__head">
      <span class="${severityBadgeClass(alert.severity)}">${escapeHtml(alert.severity)}</span>
      <span class="finding-item__type">${escapeHtml(alert.sinkType)}</span>
      <time class="finding-item__time">${escapeHtml(alert.time)}</time>
    </div>
    <p class="finding-item__desc">${escapeHtml(alert.description)}</p>
    ${alert.sample ? `<code class="finding-item__sample">${escapeHtml(alert.sample)}</code>` : ""}
  `;

  listEl.prepend(li);

  // Evita crescimento ilimitado da lista em paginas muito "ruidosas".
  const items = listEl.querySelectorAll(".finding-item--dynamic");
  if (items.length > MAX_DYNAMIC_ALERTS) {
    items[items.length - 1].remove();
  }
}

// Normaliza o formato esperado de mensagem enviada pelo relay da
// interceptacao dinamica. Mantido em uma funcao isolada para facilitar
// ajuste caso o formato real da mensagem mude.
function normalizeDynamicMessage(message) {
  if (!message || message.type !== MESSAGE_TYPE_DYNAMIC_ALERT) return null;

  const data = message.payload || {};
  return {
    sinkType: data.sinkType || "sink-desconhecido",
    severity: data.severity || "media",
    description: data.description || "Sink potencialmente perigoso interceptado em tempo de execucao.",
    sample: data.sample ? String(data.sample).slice(0, 180) : null,
    time: new Date().toLocaleTimeString("pt-BR"),
  };
}

// ---- Obtem a aba ativa de forma segura ----
async function getActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.id) {
    throw new Error("Nao foi possivel identificar a aba ativa.");
  }
  return tab;
}

// Algumas paginas (chrome://, Chrome Web Store, paginas de erro, PDFs nativos)
// nao permitem injecao de scripting por politica do navegador.
function isInjectableUrl(url) {
  if (!url) return false;
  return /^https?:\/\//i.test(url) || /^file:\/\//i.test(url);
}

// =============================================================
// init(root, ctx) - chamado pelo shell ao montar esta view.
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

  async function runStaticScan() {
    if (isScanning) return;
    isScanning = true;
    startBtn.disabled = true;
    staticBlock.dataset.state = "loading";
    setStatus("Analisando pagina atual...", "loading");

    try {
      const tab = await getActiveTab();

      if (!isInjectableUrl(tab.url)) {
        throw new Error(
          "Esta pagina nao permite analise (ex.: paginas internas do navegador ou da Chrome Web Store)."
        );
      }

      const [injectionResult] = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: staticAnalysisProbe,
      });

      if (!injectionResult || !injectionResult.result) {
        throw new Error("A analise nao retornou resultados.");
      }

      const payload = injectionResult.result;
      renderStaticResults(staticResultsEl, payload);
      staticBlock.dataset.state = "done";

      // Guarda o ultimo resultado no estado compartilhado, para uso
      // posterior (ex.: geracao do relatorio em PDF pelo shell).
      ctx.state.lastStaticScan = payload;

      const total = payload.findings.length;
      setStatus(
        total === 0
          ? "Analise concluida: nenhum problema encontrado."
          : `Analise concluida: ${total} ponto(s) de atencao.`,
        total === 0 ? "ok" : "warn"
      );
    } catch (err) {
      console.error("[NavSec] Falha na analise estatica:", err);
      staticBlock.dataset.state = "error";
      staticResultsEl.innerHTML = `
        <p class="empty-state empty-state--error">
          ⚠️ ${escapeHtml(err.message || "Erro desconhecido ao executar a analise.")}
        </p>`;
      setStatus("Falha ao analisar a pagina.", "error");
    } finally {
      isScanning = false;
      startBtn.disabled = false;
    }
  }

  startBtn.addEventListener("click", runStaticScan);

  // ---- Interceptacao Dinamica: listener de mensagens em tempo real ----
  // Cada alerta deve chegar no formato:
  //   { type: "navsec:dynamic-sink-detected", payload: { sinkType, severity, description, sample } }
  function handleRuntimeMessage(message, _sender, _sendResponse) {
    const alert = normalizeDynamicMessage(message);
    if (!alert) return; // mensagem nao pertence a esta funcionalidade

    dynamicBlock.dataset.state = "active";
    appendDynamicAlert(dynamicResultsEl, alert);

    // Mantem um registro acumulado no estado compartilhado para o relatorio.
    if (!Array.isArray(ctx.state.dynamicAlerts)) ctx.state.dynamicAlerts = [];
    ctx.state.dynamicAlerts.push(alert);
  }

  chrome.runtime.onMessage.addListener(handleRuntimeMessage);

  // Se a view for desmontada/recarregada, evita acumular listeners duplicados.
  // O shell atual nao expoe um hook de "destroy", mas deixamos o ponto de
  // extensao preparado: remova o listener aqui caso esse hook seja adicionado.
  ctx.state.cleanupVulnerabilidadesView = () => {
    chrome.runtime.onMessage.removeListener(handleRuntimeMessage);
  };

  // Repopula a lista dinamica caso o usuario volte para esta tela e ja
  // existam alertas acumulados anteriormente na sessao do popup.
  if (Array.isArray(ctx.state.dynamicAlerts) && ctx.state.dynamicAlerts.length > 0) {
    dynamicBlock.dataset.state = "active";
    ctx.state.dynamicAlerts.forEach((alert) => appendDynamicAlert(dynamicResultsEl, alert));
  }

  // Repopula o resultado estatico anterior, se houver, sem precisar re-escanear.
  // Caso contrario (primeira vez que esta tela e aberta nesta sessao do
  // popup), dispara a analise estatica automaticamente - o usuario nao
  // precisa clicar no botao para ver o primeiro resultado.
  if (ctx.state.lastStaticScan) {
    staticBlock.dataset.state = "done";
    renderStaticResults(staticResultsEl, ctx.state.lastStaticScan);
  } else {
    runStaticScan();
  }
}