// =============================================================
// sink-interceptor.js  -  Interceptação Dinâmica de Sinks.
// Roda no MAIN world (mesmo contexto JS da página), injetado via
// content_scripts com "world": "MAIN" e run_at: "document_start".
//
// IMPORTANTE: scripts no MAIN world NÃO têm acesso a chrome.* (chrome.runtime,
// chrome.storage etc). Por isso este arquivo nunca chama chrome.runtime
// diretamente. Em vez disso, emite um CustomEvent no próprio documento;
// quem ouve esse evento e repassa para a extensão é o sink-relay.js, que
// roda no ISOLATED world.
//
// Estratégia: sobrescrever (monkey-patch) os sinks mais comuns de XSS/DOM
// antes que o restante da página carregue, preservando o comportamento
// original. Cada alerta carrega: tipo de vulnerabilidade legível (vulnClass),
// CWE, localização (path + stack) e uma demonstração (PoC) inerte.
// =============================================================

(function () {
  "use strict";

  const EVENT_NAME = "__navsec_sink_event__";

  if (window.__navsecInterceptorInstalled__) return;
  window.__navsecInterceptorInstalled__ = true;

  // Metadados por tipo de sink: classe legível, CWE e descrição do PoC.
  const META = {
    "eval": { vulnClass: "Code Injection (eval)", cwe: "CWE-95",
      poc: "Conteúdo controlado pelo atacante passado a eval() é executado como código." },
    "function-constructor": { vulnClass: "Code Injection (Function)", cwe: "CWE-95",
      poc: "Strings passadas ao construtor Function() viram código executável." },
    "document.write": { vulnClass: "DOM-based XSS (document.write)", cwe: "CWE-79",
      poc: "HTML não confiável escrito via document.write pode injetar <script>." },
    "document.writeln": { vulnClass: "DOM-based XSS (document.writeln)", cwe: "CWE-79",
      poc: "HTML não confiável escrito via document.writeln pode injetar <script>." },
    "innerHTML": { vulnClass: "DOM-based XSS (innerHTML)", cwe: "CWE-79",
      poc: "Atribuir HTML não sanitizado a innerHTML executa handlers como onerror." },
    "outerHTML": { vulnClass: "DOM-based XSS (outerHTML)", cwe: "CWE-79",
      poc: "Atribuir HTML não sanitizado a outerHTML executa handlers como onerror." },
    "insertAdjacentHTML": { vulnClass: "DOM-based XSS (insertAdjacentHTML)", cwe: "CWE-79",
      poc: "HTML não sanitizado inserido via insertAdjacentHTML pode conter scripts." },
    "setattribute-event-handler": { vulnClass: "DOM-based XSS (handler dinâmico)", cwe: "CWE-79",
      poc: "Definir um atributo on* via setAttribute registra código executável." },
    "setattribute-javascript-uri": { vulnClass: "XSS (esquema javascript:)", cwe: "CWE-79",
      poc: "href/src com javascript: executa código ao ser acionado." },
    "navigation": { vulnClass: "Navegação (informativo)", cwe: null,
      poc: "Redirecionamento observado; avalie se o destino é controlável pelo usuário." },
    "postmessage-listener": { vulnClass: "postMessage sem validação de origem", cwe: "CWE-345",
      poc: "Handler de 'message' que não checa event.origin pode aceitar dados forjados." },
  };

  function captureStack() {
    try {
      const stack = new Error().stack || "";
      // Pula as primeiras linhas (Error + emit + interceptor) e mantém o
      // contexto relevante da página.
      return stack.split("\n").slice(3, 7).join("\n").trim() || null;
    } catch (_e) {
      return null;
    }
  }

  function emit(sinkType, severity, description, sample) {
    try {
      const meta = META[sinkType] || {};
      document.dispatchEvent(
        new CustomEvent(EVENT_NAME, {
          detail: {
            sinkType,
            severity,
            description,
            sample: sample != null ? String(sample).slice(0, 180) : null,
            vulnClass: meta.vulnClass || sinkType,
            cwe: meta.cwe || null,
            poc: meta.poc || null,
            location: { path: location.pathname, stack: captureStack() },
          },
        })
      );
    } catch (_err) {
      // Nunca deixa a instrumentação quebrar a página hospedeira.
    }
  }

  // ---- 1) eval() ----
  const originalEval = window.eval;
  window.eval = function (code) {
    emit("eval", "alta", "Chamada a eval() detectada — execução dinâmica de código arbitrário.", code);
    return originalEval.apply(this, arguments);
  };

  // ---- 2) Function() construtor ----
  const OriginalFunction = window.Function;
  window.Function = function (...args) {
    emit("function-constructor", "alta", "Construtor Function() usado para gerar código dinamicamente.", args.join(", "));
    return OriginalFunction.apply(this, args);
  };
  window.Function.prototype = OriginalFunction.prototype;

  // ---- 3) document.write / writeln ----
  ["write", "writeln"].forEach((method) => {
    const original = Document.prototype[method];
    Document.prototype[method] = function (...args) {
      emit(`document.${method}`, "media", `document.${method}() detectado — pode introduzir HTML não confiável no DOM.`, args.join(""));
      return original.apply(this, args);
    };
  });

  // ---- 4) innerHTML / outerHTML ----
  function hookHtmlProperty(prototype, propName) {
    const descriptor = Object.getOwnPropertyDescriptor(prototype, propName);
    if (!descriptor || !descriptor.set) return;
    Object.defineProperty(prototype, propName, {
      configurable: true,
      enumerable: descriptor.enumerable,
      get: descriptor.get,
      set: function (value) {
        if (typeof value === "string" && /<\s*script|on\w+\s*=|javascript:/i.test(value)) {
          emit(propName, "alta", `Atribuição a ${propName} com conteúdo suspeito (tag <script>, handler inline ou javascript:).`, value);
        }
        return descriptor.set.call(this, value);
      },
    });
  }
  hookHtmlProperty(Element.prototype, "innerHTML");
  hookHtmlProperty(Element.prototype, "outerHTML");

  // ---- 5) insertAdjacentHTML ----
  const originalInsertAdjacentHTML = Element.prototype.insertAdjacentHTML;
  Element.prototype.insertAdjacentHTML = function (position, html) {
    if (typeof html === "string" && /<\s*script|on\w+\s*=|javascript:/i.test(html)) {
      emit("insertAdjacentHTML", "alta", "insertAdjacentHTML() com conteúdo suspeito (tag <script>, handler inline ou javascript:).", html);
    }
    return originalInsertAdjacentHTML.apply(this, arguments);
  };

  // ---- 6) setAttribute (handlers on* ou href/src javascript:) ----
  const originalSetAttribute = Element.prototype.setAttribute;
  Element.prototype.setAttribute = function (name, value) {
    const lowerName = String(name).toLowerCase();
    if (lowerName.startsWith("on")) {
      emit("setattribute-event-handler", "media", `setAttribute() definindo um handler de evento ("${lowerName}") dinamicamente.`, value);
    } else if ((lowerName === "href" || lowerName === "src") && typeof value === "string" && /^\s*javascript:/i.test(value)) {
      emit("setattribute-javascript-uri", "alta", `setAttribute() definindo "${lowerName}" com esquema javascript:.`, value);
    }
    return originalSetAttribute.apply(this, arguments);
  };

  // ---- 7) navegação (informativo) ----
  window.addEventListener("beforeunload", () => {
    emit("navigation", "baixa", "Navegação/redirecionamento detectado a partir da página (informativo).", location.href);
  }, { capture: true });

  // ---- 8) listener de postMessage sem validação de origem (informativo) ----
  const originalAddEventListener = EventTarget.prototype.addEventListener;
  EventTarget.prototype.addEventListener = function (type, listener, options) {
    if (type === "message" && this === window) {
      emit("postmessage-listener", "baixa", "Página registrou um listener para eventos 'message'. Verifique se a origem (event.origin) é validada no handler.", null);
    }
    return originalAddEventListener.apply(this, arguments);
  };
})();
