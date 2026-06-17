// =============================================================
// sink-relay.js  -  Ponte entre o MAIN world e a extensao.
// Roda no ISOLATED world (padrao de content_scripts), no mesmo documento
// que o sink-interceptor.js (MAIN world). Os dois compartilham o DOM da
// pagina, mas NAO compartilham variaveis JS - por isso a comunicacao entre
// eles e feita via CustomEvent no document, e nao por import/referencia
// direta.
//
// Responsabilidade unica deste arquivo: ouvir o evento customizado disparado
// pelo sink-interceptor.js e reenviar para a extensao via
// chrome.runtime.sendMessage, no formato que vulnerabilidades.js espera:
//   { type: "navsec:dynamic-sink-detected", payload: { sinkType, severity, description, sample } }
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

    // chrome.runtime pode estar indisponivel momentaneamente (ex.: durante
    // reload/atualizacao da extensao) - falha silenciosa para nao gerar
    // ruido no console da pagina hospedeira.
    if (!chrome || !chrome.runtime || !chrome.runtime.sendMessage) return;

    try {
      chrome.runtime.sendMessage({
        type: MESSAGE_TYPE,
        payload: {
          sinkType: detail.sinkType,
          severity: detail.severity,
          description: detail.description,
          sample: detail.sample,
        },
      });
    } catch (err) {
      // "Extension context invalidated" e o erro mais comum aqui (ex.:
      // extensao foi recarregada com a pagina ainda aberta). Nao ha acao
      // util a tomar alem de ignorar - o content script sera reinjetado
      // no proximo carregamento de pagina.
    }
  });
})();
