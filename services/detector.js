// =============================================================
// detector.js  -  Modulo de coleta de tecnologias da pagina.
//
// Estrategia (Manifest V3):
//   o content script roda em "mundo isolado" e NAO ve os objetos
//   globais da pagina (window.jQuery, etc). Para le-los, injetamos
//   uma funcao no MAIN world via chrome.scripting.executeScript.
//
// Retorna sempre um objeto { status, ... } para a UI tratar os casos:
//   ok | restricted | no-tab | unsupported | error
// =============================================================

import { FINGERPRINTS } from "./fingerprints.js";

// -------------------------------------------------------------
// Funcao executada DENTRO da pagina (MAIN world).
// Importante: nao pode referenciar nada de fora; so usa o argumento
// recebido, window, document e location. E serializada e injetada.
// -------------------------------------------------------------
function collectInPage(fingerprints) {
  function read(path) {
    try {
      return path.split(".").reduce(function (obj, key) {
        return obj == null ? undefined : obj[key];
      }, window);
    } catch (e) {
      return undefined;
    }
  }

  // URLs dos <script src> da pagina (fallback de deteccao por arquivo).
  var scripts = [];
  try {
    var nodes = document.querySelectorAll("script[src]");
    for (var n = 0; n < nodes.length; n++) scripts.push(nodes[n].src || "");
  } catch (e) {}

  var found = [];

  for (var i = 0; i < fingerprints.length; i++) {
    var fp = fingerprints[i];
    var version = null;
    var via = "global";
    var strongGlobal = false; // global com nome != "$"/"_" (menos ambiguo)

    // 1) Presenca por objeto global.
    for (var j = 0; j < fp.globals.length; j++) {
      var g = fp.globals[j];
      if (read(g) !== undefined && g.length > 1) strongGlobal = true;
    }

    // 2) Versao em runtime (mais confiavel).
    for (var k = 0; k < fp.versionPaths.length; k++) {
      var v = read(fp.versionPaths[k]);
      if (typeof v === "string" && v) { version = v; via = "runtime"; break; }
      if (typeof v === "number") { version = String(v); via = "runtime"; break; }
    }

    // 3) Fallback: versao a partir do nome do arquivo no <script src>.
    if (version == null && fp.srcPattern) {
      try {
        var re = new RegExp(fp.srcPattern, "i");
        for (var s = 0; s < scripts.length; s++) {
          var m = scripts[s].match(re);
          if (m) { version = m[1] || "desconhecida"; via = "src"; break; }
        }
      } catch (e) {}
    }

    // So considera detectada se houver versao OU um global pouco ambiguo.
    var detected = version != null || strongGlobal;
    if (!detected) continue;

    found.push({
      id: fp.id,
      name: fp.name,
      version: version || "desconhecida",
      via: via,
    });
  }

  return { url: location.href, technologies: found, scannedAt: Date.now() };
}

// Paginas em que extensoes nao podem injetar scripts.
const RESTRICTED = /^(chrome|edge|brave|opera|vivaldi|about|chrome-extension|moz-extension|view-source|devtools|data):/i;

function isRestricted(url) {
  if (!url) return false;
  if (RESTRICTED.test(url)) return true;
  return (
    url.indexOf("https://chrome.google.com/webstore") === 0 ||
    url.indexOf("https://chromewebstore.google.com") === 0
  );
}

// -------------------------------------------------------------
// API publica: detecta as tecnologias da aba ativa.
// -------------------------------------------------------------
export async function detectTechnologies() {
  if (typeof chrome === "undefined" || !chrome.scripting || !chrome.tabs) {
    return { status: "unsupported" };
  }

  let tab;
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    tab = tabs && tabs[0];
  } catch (e) {
    return { status: "error", message: String(e) };
  }
  if (!tab || tab.id == null) return { status: "no-tab" };

  if (isRestricted(tab.url)) {
    return { status: "restricted", url: tab.url || "" };
  }

  let result;
  try {
    const injection = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      world: "MAIN",
      func: collectInPage,
      args: [FINGERPRINTS],
    });
    result = injection && injection[0] ? injection[0].result : null;
  } catch (e) {
    // Falha de injecao costuma significar pagina protegida.
    return { status: "restricted", url: tab.url || "", message: String(e && e.message ? e.message : e) };
  }

  if (!result) return { status: "error", message: "A pagina nao retornou dados." };

  return {
    status: "ok",
    url: result.url || tab.url || "",
    technologies: result.technologies || [],
    scannedAt: result.scannedAt,
  };
}
