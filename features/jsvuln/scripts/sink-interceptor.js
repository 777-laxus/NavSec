// =============================================================
// sink-interceptor.js  -  Interceptacao Dinamica de Sinks.
// Roda no MAIN world (mesmo contexto JS da pagina), injetado via
// content_scripts com "world": "MAIN" e run_at: "document_start".
//
// IMPORTANTE: scripts no MAIN world NAO tem acesso a chrome.* (chrome.runtime,
// chrome.storage etc). Por isso este arquivo nunca chama chrome.runtime
// diretamente. Em vez disso, ele emite um CustomEvent no proprio documento;
// quem ouve esse evento e repassa para a extensao e o sink-relay.js, que
// roda no ISOLATED world (tem acesso a chrome.runtime, mas nao consegue
// sobrescrever os metodos nativos da pagina por causa do isolamento de
// contexto -- por isso a divisao em dois scripts).
//
// Estrategia: sobrescrever (monkey-patch) os sinks mais comuns de XSS/DOM
// antes que o restante da pagina carregue, preservando o comportamento
// original via Function.prototype.apply/Reflect.
// =============================================================

(function () {
  "use strict";

  const EVENT_NAME = "__navsec_sink_event__";

  // Evita instalar os hooks duas vezes (ex.: re-injecao acidental).
  if (window.__navsecInterceptorInstalled__) return;
  window.__navsecInterceptorInstalled__ = true;

  function emit(sinkType, severity, description, sample) {
    try {
      document.dispatchEvent(
        new CustomEvent(EVENT_NAME, {
          detail: {
            sinkType,
            severity,
            description,
            sample: sample != null ? String(sample).slice(0, 180) : null,
          },
        })
      );
    } catch (_err) {
      // Nunca deixa a instrumentacao quebrar a pagina hospedeira.
    }
  }

  // ---- 1) eval() ----
  const originalEval = window.eval;
  window.eval = function (code) {
    emit(
      "eval",
      "alta",
      "Chamada a eval() detectada - execucao dinamica de codigo arbitrario.",
      code
    );
    return originalEval.apply(this, arguments);
  };

  // ---- 2) Function() construtor (equivalente a eval) ----
  const OriginalFunction = window.Function;
  window.Function = function (...args) {
    emit(
      "function-constructor",
      "alta",
      "Construtor Function() usado para gerar codigo dinamicamente.",
      args.join(", ")
    );
    return OriginalFunction.apply(this, args);
  };
  window.Function.prototype = OriginalFunction.prototype;

  // ---- 3) document.write / writeln ----
  ["write", "writeln"].forEach((method) => {
    const original = Document.prototype[method];
    Document.prototype[method] = function (...args) {
      emit(
        `document.${method}`,
        "media",
        `document.${method}() detectado - pode introduzir HTML nao confiavel no DOM.`,
        args.join("")
      );
      return original.apply(this, args);
    };
  });

  // ---- 4) innerHTML / outerHTML (via Object.defineProperty no prototype) ----
  function hookHtmlProperty(prototype, propName) {
    const descriptor = Object.getOwnPropertyDescriptor(prototype, propName);
    if (!descriptor || !descriptor.set) return;

    Object.defineProperty(prototype, propName, {
      configurable: true,
      enumerable: descriptor.enumerable,
      get: descriptor.get,
      set: function (value) {
        if (typeof value === "string" && /<\s*script|on\w+\s*=|javascript:/i.test(value)) {
          emit(
            propName,
            "alta",
            `Atribuicao a ${propName} com conteudo suspeito (tag <script>, handler inline ou javascript:).`,
            value
          );
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
      emit(
        "insertAdjacentHTML",
        "alta",
        "insertAdjacentHTML() com conteudo suspeito (tag <script>, handler inline ou javascript:).",
        html
      );
    }
    return originalInsertAdjacentHTML.apply(this, arguments);
  };

  // ---- 6) setAttribute para atributos de evento (on*) ou href/src javascript: ----
  const originalSetAttribute = Element.prototype.setAttribute;
  Element.prototype.setAttribute = function (name, value) {
    const lowerName = String(name).toLowerCase();
    if (lowerName.startsWith("on")) {
      emit(
        "setattribute-event-handler",
        "media",
        `setAttribute() definindo um handler de evento ("${lowerName}") dinamicamente.`,
        value
      );
    } else if (
      (lowerName === "href" || lowerName === "src") &&
      typeof value === "string" &&
      /^\s*javascript:/i.test(value)
    ) {
      emit(
        "setattribute-javascript-uri",
        "alta",
        `setAttribute() definindo "${lowerName}" com esquema javascript:.`,
        value
      );
    }
    return originalSetAttribute.apply(this, arguments);
  };

  // ---- 7) location assignment direta (location.href = ..., location = ...) ----
  // Nao e possivel sobrescrever window.location diretamente em todos os
  // browsers, mas podemos observar mudancas via beforeunload como sinal
  // indireto sem quebrar a navegacao normal da pagina.
  window.addEventListener(
    "beforeunload",
    () => {
      emit(
        "navigation",
        "baixa",
        "Navegacao/redirecionamento detectado a partir da pagina (informativo).",
        location.href
      );
    },
    { capture: true }
  );

  // ---- 8) postMessage recebido sem validacao de origem pela propria pagina ----
  // Apenas informativo: alerta quando a pagina registra um listener de
  // "message" - nao indica vulnerabilidade por si só, mas e relevante para
  // a analise manual.
  const originalAddEventListener = EventTarget.prototype.addEventListener;
  EventTarget.prototype.addEventListener = function (type, listener, options) {
    if (type === "message" && this === window) {
      emit(
        "postmessage-listener",
        "baixa",
        "Pagina registrou um listener para eventos 'message'. Verifique se a origem (event.origin) e validada no handler.",
        null
      );
    }
    return originalAddEventListener.apply(this, arguments);
  };
})();
