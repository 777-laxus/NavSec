// =============================================================
// sink-relay.js  -  Ponte entre o MAIN world e a extensão.
// Roda no ISOLATED world, no mesmo documento que o sink-interceptor.js.
// Ouve o CustomEvent disparado pelo interceptor e reenvia para a extensão
// via chrome.runtime.sendMessage, repassando TODOS os campos do alerta
// (sinkType, severity, description, sample, vulnClass, cwe, poc, location).
// =============================================================

(function () {
  "use strict";

  const EVENT_NAME = "__navsec_sink_event__";
  const MESSAGE_TYPE = "navsec:dynamic-sink-detected";

  if (window.__navsecRelayInstalled__) return;
  window.__navsecRelayInstalled__ = true;

  document.addEventListener(EVENT_NAME, (event) => {
    const detail = event && event.detail;
    if (!detail) return;
    if (!chrome || !chrome.runtime || !chrome.runtime.sendMessage) return;

    try {
      // Repassa o objeto de detalhe inteiro como payload.
      chrome.runtime.sendMessage({ type: MESSAGE_TYPE, payload: detail });
    } catch (err) {
      // "Extension context invalidated" (ex.: extensão recarregada) — ignora.
    }
  });
})();
