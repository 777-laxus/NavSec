// =============================================================
// view-loader.js  -  Carregamento de recursos de uma view.
// Resolve caminhos para a URL interna da extensao, faz cache de
// CSS e de modulos ja importados e busca o HTML da view.
// =============================================================

const loadedCss = new Set();
const loadedModules = new Map();

function resolve(path) {
  if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.getURL) {
    return chrome.runtime.getURL(path);
  }
  return path;
}

export function ensureCss(path) {
  if (!path || loadedCss.has(path)) return;
  const link = document.createElement("link");
  link.rel = "stylesheet";
  link.href = resolve(path);
  link.dataset.viewCss = path;
  document.head.appendChild(link);
  loadedCss.add(path);
}

export async function fetchHtml(path) {
  const res = await fetch(resolve(path));
  if (!res.ok) throw new Error("HTTP " + res.status + " ao carregar " + path);
  return res.text();
}

export async function loadModule(path) {
  if (loadedModules.has(path)) return loadedModules.get(path);
  const mod = await import(resolve(path));
  loadedModules.set(path, mod);
  return mod;
}
