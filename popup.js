// =============================================================
// popup.js  -  Bootstrap da aplicacao (shell).
// Cria o roteador, registra as features e liga os controles do
// shell (chevrons = troca de feature, dots, botao PDF, teclado).
// A logica de cada tela vive nas features; aqui fica so o nucleo.
// =============================================================

import { createRouter } from "./core/router.js";
import { FEATURES } from "./core/features.js";
import { downloadReport } from "./services/report.js";

const mount = document.getElementById("content-area");
const subtitleEl = document.getElementById("header-subtitle");
const dotsEl = document.getElementById("nav-dots");

const router = createRouter({
  features: FEATURES,
  mount,
  onFeatureChange: (feature, index) => {
    subtitleEl.textContent = feature.title;
    renderDots(index);
  },
});

function renderDots(activeIndex) {
  dotsEl.innerHTML = "";
  FEATURES.forEach((feature, i) => {
    const dot = document.createElement("button");
    dot.type = "button";
    dot.className = "dot" + (i === activeIndex ? " dot--active" : "");
    dot.title = feature.title;
    dot.setAttribute("aria-label", "Ir para " + feature.title);
    dot.addEventListener("click", () => router.goToIndex(i));
    dotsEl.appendChild(dot);
  });
}

// ---- Controles do shell ----
document.getElementById("nav-prev").addEventListener("click", () => router.prev());
document.getElementById("nav-next").addEventListener("click", () => router.next());
document.getElementById("btn-pdf").addEventListener("click", () => {
  try {
    downloadReport(router.state.scan);
  } catch (err) {
    console.error("[NavSec] falha ao gerar o relatorio", err);
  }
});

// Setas do teclado trocam de feature.
document.addEventListener("keydown", (e) => {
  if (e.key === "ArrowLeft") router.prev();
  else if (e.key === "ArrowRight") router.next();
});

// ---- Inicio ----
router.start();
