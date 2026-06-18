// =============================================================
// cve.js  -  Consulta de vulnerabilidades (CVE) por versao.
//
// Fonte: OSV.dev (https://osv.dev) - gratuito, consulta por
// pacote + versao no ecossistema npm. Para cada tecnologia
// coletada, descobre as CVE ativas, calcula a severidade (CVSS
// v3.1), determina a versao corrigida e monta o link oficial.
//
// Requer host_permissions para https://api.osv.dev/* no manifest.
// =============================================================

const OSV_QUERY_URL = "https://api.osv.dev/v1/query";
const ECOSYSTEM = "npm";

// id da fingerprint -> nome do pacote no npm
const PACKAGE_NAMES = {
  jquery: "jquery",
  angularjs: "angular", // AngularJS 1.x no npm chama-se "angular"
  vue: "vue",
  lodash: "lodash",
  moment: "moment",
  bootstrap: "bootstrap",
};

// -------------------------------------------------------------
// CVSS v3.0/3.1 - calculo da nota base a partir do vetor.
// -------------------------------------------------------------
const M = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  C: { H: 0.56, L: 0.22, N: 0 },
  I: { H: 0.56, L: 0.22, N: 0 },
  A: { H: 0.56, L: 0.22, N: 0 },
  PR_U: { N: 0.85, L: 0.62, H: 0.27 },
  PR_C: { N: 0.85, L: 0.68, H: 0.5 },
};

function roundUp1(input) {
  const i = Math.round(input * 100000);
  if (i % 10000 === 0) return i / 100000;
  return (Math.floor(i / 10000) + 1) / 10;
}

// Retorna { score, label } ou null se nao for um vetor V3 valido.
function cvssV3BaseScore(vector) {
  if (!vector || vector.indexOf("CVSS:3") !== 0) return null;
  const parts = {};
  vector.split("/").forEach((seg) => {
    const [k, v] = seg.split(":");
    parts[k] = v;
  });
  try {
    const scopeChanged = parts.S === "C";
    const prTable = scopeChanged ? M.PR_C : M.PR_U;
    const av = M.AV[parts.AV], ac = M.AC[parts.AC], pr = prTable[parts.PR];
    const ui = M.UI[parts.UI], c = M.C[parts.C], ii = M.I[parts.I], a = M.A[parts.A];
    if ([av, ac, pr, ui, c, ii, a].some((x) => x === undefined)) return null;

    const iss = 1 - (1 - c) * (1 - ii) * (1 - a);
    const impact = scopeChanged
      ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
      : 6.42 * iss;
    const exploitability = 8.22 * av * ac * pr * ui;

    let base;
    if (impact <= 0) base = 0;
    else if (scopeChanged) base = roundUp1(Math.min(1.08 * (impact + exploitability), 10));
    else base = roundUp1(Math.min(impact + exploitability, 10));

    return { score: base, label: scoreLabel(base) };
  } catch (e) {
    return null;
  }
}

function scoreLabel(score) {
  if (score >= 9.0) return "Crítica";
  if (score >= 7.0) return "Alta";
  if (score >= 4.0) return "Média";
  if (score > 0) return "Baixa";
  return "Nenhuma";
}

// Mapeia para os 3 niveis da UI (badge): alto | medio | ok
function riskFromScore(score, qualitative) {
  if (typeof score === "number") return score >= 7.0 ? "alto" : "medio";
  if (qualitative) {
    const q = String(qualitative).toUpperCase();
    if (q === "CRITICAL" || q === "HIGH") return "alto";
    if (q === "MODERATE" || q === "MEDIUM" || q === "LOW") return "medio";
  }
  return "medio";
}

// -------------------------------------------------------------
// Versao corrigida: maior "fixed" entre as faixas afetadas.
// -------------------------------------------------------------
function cmpVersion(a, b) {
  const pa = String(a).split(".").map((n) => parseInt(n, 10) || 0);
  const pb = String(b).split(".").map((n) => parseInt(n, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] || 0) - (pb[i] || 0);
    if (d !== 0) return d;
  }
  return 0;
}

function computeFixedVersion(rawVulns) {
  let best = null;
  (rawVulns || []).forEach((v) => {
    (v.affected || []).forEach((aff) => {
      (aff.ranges || []).forEach((range) => {
        (range.events || []).forEach((ev) => {
          if (ev.fixed && (best === null || cmpVersion(ev.fixed, best) > 0)) best = ev.fixed;
        });
      });
    });
  });
  return best;
}

// -------------------------------------------------------------
// Normaliza uma vulnerabilidade do OSV no formato usado pela UI.
// -------------------------------------------------------------
function pickReference(cve, references, osvId) {
  if (cve) return "https://nvd.nist.gov/vuln/detail/" + cve;
  const advisory = (references || []).find((r) => r.type === "ADVISORY");
  if (advisory && advisory.url) return advisory.url;
  const any = (references || []).find((r) => r.url);
  if (any) return any.url;
  return "https://osv.dev/vulnerability/" + osvId;
}

function normalizeVuln(v) {
  const aliases = v.aliases || [];
  const cve =
    aliases.find((a) => a.indexOf("CVE-") === 0) ||
    (String(v.id).indexOf("CVE-") === 0 ? v.id : null);

  // CVSS v3 (preferencial)
  let cvss = null;
  (v.severity || []).forEach((s) => {
    if (!cvss && s.type && s.type.indexOf("CVSS_V3") === 0) cvss = cvssV3BaseScore(s.score);
  });

  const ds = v.database_specific || {};
  const cwe = Array.isArray(ds.cwe_ids) && ds.cwe_ids.length ? ds.cwe_ids.join(", ") : null;
  const qualitative = ds.severity || null;

  return {
    osvId: v.id,
    cve: cve,
    displayId: cve || v.id,
    summary: v.summary || "",
    details: v.details || "",
    cwe: cwe,
    score: cvss ? cvss.score : null,
    scoreLabel: cvss ? cvss.label : (qualitative ? qualitative : null),
    qualitative: qualitative,
    url: pickReference(cve, v.references, v.id),
  };
}

// -------------------------------------------------------------
// API publica: consulta as CVE de UMA tecnologia coletada.
// Recebe { id, name, version, via } e devolve a tecnologia
// enriquecida com { status, vulns, cveCount, risk, worst, fixedVersion }.
// -------------------------------------------------------------
export async function queryTech(tech) {
  const base = { ...tech, status: "ok", vulns: [], cveCount: 0, risk: "ok", worst: null, fixedVersion: null };

  const pkg = PACKAGE_NAMES[tech.id];
  if (!pkg || tech.version === "desconhecida") {
    return { ...base, status: "skipped", risk: "pendente" };
  }

  let data;
  try {
    const res = await fetch(OSV_QUERY_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ version: tech.version, package: { name: pkg, ecosystem: ECOSYSTEM } }),
    });
    if (!res.ok) throw new Error("HTTP " + res.status);
    data = await res.json();
  } catch (e) {
    return { ...base, status: "error", risk: "pendente", error: String(e && e.message ? e.message : e) };
  }

  const raw = data.vulns || [];
  const vulns = raw.map(normalizeVuln);
  // mais grave primeiro (por nota; sem nota vai para o fim)
  vulns.sort((a, b) => (b.score || 0) - (a.score || 0));

  const worst = vulns[0] || null;
  const fixedVersion = computeFixedVersion(raw);
  const risk = vulns.length ? riskFromScore(worst ? worst.score : null, worst ? worst.qualitative : null) : "ok";

  return { ...base, status: "ok", vulns, cveCount: vulns.length, risk, worst, fixedVersion };
}

// Consulta todas as tecnologias em paralelo.
export async function queryAll(technologies) {
  return Promise.all((technologies || []).map(queryTech));
}
