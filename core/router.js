// =============================================================
// router.js  -  Roteador leve da aplicacao.
//
// Conceitos:
//   - feature: um modulo de alto nivel (Stacks, JS Vuln, Reputacao).
//     Os chevrons/dots alternam entre features (navegacao circular).
//   - rota: uma view dentro de uma feature (ex.: stacks -> list/detail).
//   - historico: pilha interna por sessao, usada pelo "voltar" dentro
//     da feature (lista <-> detalhe), sem cruzar para outras features.
//
// O estado compartilhado (state) vive aqui e e injetado em cada view
// junto do proprio router (injecao de dependencias).
// =============================================================

import { ensureCss, fetchHtml, loadModule } from "./view-loader.js";

export function createRouter(options) {
  const features = options.features;
  const mount = options.mount;
  const onFeatureChange = options.onFeatureChange || function () {};

  // Estado compartilhado entre views/features durante a sessao do popup.
  const state = { scan: null, selectedStackId: null };

  let featureIndex = 0;
  let history = []; // [{ featureId, route, params }]

  function featureById(id) {
    return features.find((f) => f.id === id);
  }
  function currentFeature() {
    return features[featureIndex];
  }

  async function renderEntry(entry) {
    const feature = featureById(entry.featureId);
    const route = feature && feature.routes[entry.route];
    if (!route) return;

    ensureCss(route.css);

    let html;
    try {
      html = await fetchHtml(route.html);
    } catch (err) {
      console.error("[NavSec]", err);
      mount.innerHTML = '<div class="state-message"><strong>Falha ao carregar a tela</strong><span>Tente reabrir a extensao.</span></div>';
      return;
    }

    mount.classList.remove("is-visible");
    mount.innerHTML = html;
    mount.scrollTop = 0;

    const ctx = {
      state: state,
      params: entry.params || {},
      routeData: route.data || null,
      router: api,
    };

    try {
      const mod = await loadModule(route.script);
      if (mod && typeof mod.init === "function") await mod.init(mount, ctx);
    } catch (err) {
      console.error("[NavSec] init de view falhou:", entry.featureId + "/" + entry.route, err);
    }

    requestAnimationFrame(() => mount.classList.add("is-visible"));
    onFeatureChange(feature, featureIndex);
  }

  const api = {
    state: state,

    get features() {
      return features;
    },
    get index() {
      return featureIndex;
    },
    currentFeatureId() {
      return currentFeature().id;
    },

    // ---- Navegacao entre features (chevrons / dots) ----
    goToFeature(id) {
      const i = features.findIndex((f) => f.id === id);
      if (i < 0) return;
      featureIndex = i;
      const f = features[i];
      history = [{ featureId: f.id, route: f.initialRoute, params: {} }];
      renderEntry(history[history.length - 1]);
    },
    goToIndex(i) {
      const total = features.length;
      const idx = ((i % total) + total) % total;
      this.goToFeature(features[idx].id);
    },
    next() {
      this.goToIndex(featureIndex + 1);
    },
    prev() {
      this.goToIndex(featureIndex - 1);
    },

    // ---- Navegacao interna de uma feature (sub-rotas) ----
    navigate(route, params) {
      const f = currentFeature();
      if (!f.routes[route]) {
        console.warn("[NavSec] rota inexistente:", f.id + "/" + route);
        return;
      }
      history.push({ featureId: f.id, route: route, params: params || {} });
      renderEntry(history[history.length - 1]);
    },
    back() {
      if (history.length > 1) {
        history.pop();
        renderEntry(history[history.length - 1]);
      }
    },
    canGoBack() {
      return history.length > 1;
    },

    start() {
      this.goToFeature(features[0].id);
    },
  };

  return api;
}
