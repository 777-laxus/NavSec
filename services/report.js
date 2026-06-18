// =============================================================
// report.js — Relatório de segurança unificado (PDF válido, sem dependências).
//
// Agrega o estado COMPARTILHADO do popup (router.state) em um único PDF:
//   • Bibliotecas e CVEs        → state.scan            (feature "stacks")
//   • Vulnerabilidades DOM/JS    → state.lastStaticScan + state.dynamicAlerts (feature "jsvuln")
//   • Reputação do domínio       → state.reputation     (feature "reputation")
//
// TODOS os CVEs de cada stack são listados e linkados (NVD/GHSA), como chips
// clicáveis. Relatórios do VirusTotal/AbuseIPDB também viram links clicáveis.
//
// API pública: downloadReport(state) — recebe o router.state inteiro.
//
// PDF cru: Latin-1 (1 byte/char) + /WinAnsiEncoding (acentos OK, offsets exatos),
// múltiplas páginas, quebra de linha, rodapé e /Annots por página.
// =============================================================

// ---- tema ---------------------------------------------------
const PAGE_W = 595, PAGE_H = 842, M = 48, HEADER_H = 72;
const INK    = [0.106, 0.106, 0.098];
const MUTED  = [0.431, 0.416, 0.376];
const LINE   = [0.894, 0.882, 0.851];
const ACCENT = [0.133, 0.188, 0.247];
const LINKC  = [0.145, 0.388, 0.922];
const WHITE  = [1, 1, 1];

const RISK = {
  alto:     { rgb: [0.827, 0.227, 0.173], label: "ALTO",  title: "Alto risco" },
  medio:    { rgb: [0.878, 0.541, 0.000], label: "MÉDIO", title: "Médio risco" },
  baixa:    { rgb: [0.722, 0.525, 0.043], label: "BAIXA", title: "Baixo risco" },
  ok:       { rgb: [0.243, 0.557, 0.353], label: "OK",    title: "Em conformidade" },
  pendente: { rgb: [0.478, 0.478, 0.447], label: "N/D",   title: "Não determinado" },
};
const ORDER = ["alto", "medio", "baixa", "pendente", "ok"];

const SEV_ALIAS = {
  alto: "alto", alta: "alto", high: "alto", critical: "alto", critica: "alto", "crítica": "alto",
  medio: "medio", "médio": "medio", media: "medio", "média": "medio", medium: "medio", moderate: "medio", moderada: "medio",
  baixa: "baixa", baixo: "baixa", low: "baixa",
  ok: "ok", seguro: "ok", limpo: "ok", conforme: "ok",
  pendente: "pendente", "-": "pendente", na: "pendente", "n/a": "pendente", "n/d": "pendente", desconhecida: "pendente",
};
const normSev = (s) => SEV_ALIAS[String(s == null ? "" : s).toLowerCase()] || "pendente";

// ---- encoding / escaping ------------------------------------
const WIN_MAP = { 0x2014: 0x97, 0x2013: 0x96, 0x2018: 0x91, 0x2019: 0x92,
                  0x201c: 0x93, 0x201d: 0x94, 0x2022: 0x95, 0x2026: 0x85 };
function toWinAnsi(s) {
  let out = "";
  for (const ch of String(s)) {
    const c = ch.codePointAt(0);
    if (c <= 0xff) out += ch;
    else if (WIN_MAP[c] != null) out += String.fromCharCode(WIN_MAP[c]);
    else out += "?";
  }
  return out;
}
function escPdf(text) {
  return toWinAnsi(text).replace(/\\/g, "\\\\").replace(/\(/g, "\\(").replace(/\)/g, "\\)");
}
const f = (n) => String(Math.round(n * 100) / 100);
const clip = (s, n) => { s = String(s == null ? "" : s); return s.length > n ? s.slice(0, n - 1) + "…" : s; };

// =============================================================
// Estado → seções
// =============================================================
function normalizeInput(input) {
  if (!input) return {};
  if (input.technologies && !input.scan) return { scan: input }; // legado
  return input;
}
function statusNote(scan) {
  const map = {
    restricted: "Página interna do navegador — não analisável.",
    "no-tab": "Nenhuma aba ativa identificada.",
    unsupported: "Recurso indisponível nesta aba.",
    error: scan.message || "Falha na análise.",
  };
  return map[scan.status] || "Aba \u201CStacks\u201D não analisada nesta sessão.";
}

function buildStacksSection(scan) {
  if (!scan || scan.status !== "ok") {
    return { title: "Bibliotecas e CVEs", available: false,
             note: scan && scan.status ? statusNote(scan) : "Aba \u201CStacks\u201D não analisada nesta sessão." };
  }
  const techs = scan.technologies || [];
  if (!techs.length) {
    return { title: "Bibliotecas e CVEs", available: true,
             blocks: [{ items: [{ sev: "ok", text: "Nenhuma biblioteca conhecida detectada na página." }] }] };
  }
  const items = techs.map((t) => {
    let text = `${t.name} ${t.version}`;
    if (t.worst) {
      text += `   ·   ${t.cveCount} CVE${t.cveCount > 1 ? "s" : ""}`;
      const sc = t.worst.score != null
        ? `CVSS ${t.worst.score}${t.worst.scoreLabel ? ` (${t.worst.scoreLabel})` : ""}`
        : (t.worst.scoreLabel || "");
      if (sc) text += `   ·   pior: ${sc}`;
    } else if (t.status === "skipped") {
      text += "   ·   versão desconhecida";
    } else if (t.status === "error") {
      text += "   ·   CVE indisponível";
    } else {
      text += "   ·   sem CVE";
    }

    const bits = [];
    if (t.worst && t.worst.cwe) bits.push(t.worst.cwe);
    if (t.fixedVersion) bits.push("corrigido em " + t.fixedVersion + "+");
    const desc = bits.length ? bits.join("   ·   ") : null;

    // TODOS os CVEs como chips clicáveis (NVD/GHSA)
    const cveLinks = Array.isArray(t.vulns)
      ? t.vulns.filter((v) => v.url).map((v) => ({ label: v.displayId, url: v.url }))
      : (t.worst && t.worst.url ? [{ label: t.worst.displayId, url: t.worst.url }] : []);

    return { sev: normSev(t.risk), text, desc, cveLinks };
  });
  const note = scan.cveStatus === "partial" ? "Algumas CVEs não puderam ser consultadas (verifique a conexão)." : null;
  return { title: "Bibliotecas e CVEs", available: true, footnote: note, blocks: [{ items }] };
}

function buildJsVulnSection(staticScan, dynamicAlerts) {
  const dyn = dynamicAlerts || [];
  if (!staticScan && !dyn.length) {
    return { title: "Vulnerabilidades DOM/JS", available: false,
             note: "Aba \u201CVulnerabilidades JS\u201D não analisada nesta sessão." };
  }
  const blocks = [];
  if (staticScan) {
    const fs = staticScan.findings || [];
    if (!fs.length) {
      blocks.push({ label: "Análise estática", items: [{ sev: "ok", text: "Nenhuma vulnerabilidade evidente encontrada na análise estática." }] });
    } else {
      blocks.push({
        label: `Análise estática (${fs.length})`,
        items: fs.map((fn) => ({ sev: normSev(fn.severity), text: fn.description, desc: fn.sample ? "amostra: " + clip(fn.sample, 120) : null })),
      });
    }
  }
  if (dyn.length) {
    blocks.push({
      label: `Sinks interceptados em tempo real (${dyn.length})`,
      items: dyn.map((a) => ({ sev: normSev(a.severity), text: `${a.sinkType} — ${a.description}`, desc: a.sample ? "amostra: " + clip(a.sample, 120) : null })),
    });
  }
  return { title: "Vulnerabilidades DOM/JS", available: true, blocks };
}

function buildReputationSection(rep) {
  if (!rep) {
    return { title: "Reputação do domínio", available: false,
             note: "Aba \u201CReputação\u201D não analisada nesta sessão." };
  }
  const items = [];

  if (rep.https) items.push({ sev: normSev(rep.https.status), text: "HTTPS — " + rep.https.label });
  else items.push({ sev: "pendente", text: "HTTPS — análise não concluída." });

  if (rep.virustotal) items.push({
    sev: normSev(rep.virustotal.status), text: "VirusTotal — " + rep.virustotal.label,
    desc: rep.virustotal.desc || null, link: rep.virustotal.url ? { url: rep.virustotal.url } : null });
  else items.push({ sev: "pendente", text: "VirusTotal — análise não concluída (reabra/aguarde a aba Reputação)." });

  if (rep.abuseipdb) items.push({
    sev: normSev(rep.abuseipdb.status), text: "AbuseIPDB — " + rep.abuseipdb.label,
    desc: rep.abuseipdb.desc || null, link: rep.abuseipdb.url ? { url: rep.abuseipdb.url } : null });
  else items.push({ sev: "pendente", text: "AbuseIPDB — análise não concluída (reabra/aguarde a aba Reputação)." });

  if (rep.headers && rep.headers.length) {
    rep.headers.forEach((h) => items.push({ sev: normSev(h.status), text: `${h.name} — ${h.desc}` }));
  } else {
    items.push({ sev: "pendente", text: "Cabeçalhos de segurança — análise não concluída." });
  }

  return { title: "Reputação do domínio", available: true, blocks: [{ items }] };
}

// =============================================================
// Layout
// =============================================================
function buildStyledPdf(input) {
  const state = normalizeInput(input);
  const scan          = state.scan || null;
  const staticScan    = state.lastStaticScan || null;
  const dynamicAlerts = state.dynamicAlerts || [];
  const reputation    = state.reputation || null;

  const url = (scan && scan.url) || (staticScan && staticScan.url) || (reputation && reputation.url) || "-";
  const date = new Date().toLocaleString("pt-BR");

  const sections = [
    buildStacksSection(scan),
    buildJsVulnSection(staticScan, dynamicAlerts),
    buildReputationSection(reputation),
  ];

  const counts = { alto: 0, medio: 0, baixa: 0, ok: 0, pendente: 0 };
  sections.forEach((s) => (s.blocks || []).forEach((b) => b.items.forEach((it) => counts[it.sev]++)));

  const pages = [[]];
  const pageLinks = [[]];
  let pi = 0;
  let y = 0;
  const op = (s) => pages[pi].push(s);
  const addPage = () => { pages.push([]); pageLinks.push([]); pi++; };

  // -- primitives --
  const setFill   = ([r, g, b]) => op(`${f(r)} ${f(g)} ${f(b)} rg`);
  const setStroke = ([r, g, b]) => op(`${f(r)} ${f(g)} ${f(b)} RG`);
  const fillRect  = (x, yy, w, h, c) => { setFill(c); op(`${f(x)} ${f(yy)} ${f(w)} ${f(h)} re`); op("f"); };
  const line = (x1, y1, x2, y2, c, w = 1) => { setStroke(c); op(`${f(w)} w`); op(`${f(x1)} ${f(y1)} m ${f(x2)} ${f(y2)} l S`); };
  const circle = (cx, cy, r, c) => {
    const k = 0.5523 * r; setFill(c);
    op(`${f(cx + r)} ${f(cy)} m`);
    op(`${f(cx + r)} ${f(cy + k)} ${f(cx + k)} ${f(cy + r)} ${f(cx)} ${f(cy + r)} c`);
    op(`${f(cx - k)} ${f(cy + r)} ${f(cx - r)} ${f(cy + k)} ${f(cx - r)} ${f(cy)} c`);
    op(`${f(cx - r)} ${f(cy - k)} ${f(cx - k)} ${f(cy - r)} ${f(cx)} ${f(cy - r)} c`);
    op(`${f(cx + k)} ${f(cy - r)} ${f(cx + r)} ${f(cy - k)} ${f(cx + r)} ${f(cy)} c`);
    op("f");
  };
  const text = (x, yy, str, size, c, bold) => {
    setFill(c);
    op(`BT ${bold ? "/F2" : "/F1"} ${f(size)} Tf ${f(x)} ${f(yy)} Td (${escPdf(str)}) Tj ET`);
  };
  const textW = (str, size, bold) => toWinAnsi(String(str)).length * size * (bold ? 0.56 : 0.5);
  const clipW = (s, maxW, size) => {
    s = String(s);
    if (textW(s, size) <= maxW) return s;
    let k = s.length;
    while (k > 1 && textW(s.slice(0, k) + "…", size) > maxW) k--;
    return s.slice(0, k) + "…";
  };
  const wrap = (str, maxW, size) => {
    const lines = []; let cur = "";
    const flush = () => { lines.push(cur); cur = ""; };
    for (const word of String(str).split(/\s+/)) {
      const candidate = cur ? cur + " " + word : word;
      if (textW(candidate, size) <= maxW) { cur = candidate; continue; }
      if (cur) flush();
      let w = word;
      while (textW(w, size) > maxW) {
        let k = 1;
        while (k < w.length && textW(w.slice(0, k + 1), size) <= maxW) k++;
        lines.push(w.slice(0, k));
        w = w.slice(k);
      }
      cur = w;
    }
    if (cur) flush();
    return lines.length ? lines : [""];
  };
  // texto azul sublinhado + anotação de link clicável
  const linkLabel = (x, yy, label, url, size) => {
    text(x, yy, label, size, LINKC, false);
    const w = textW(label, size);
    line(x, yy - 1.5, x + w, yy - 1.5, LINKC, 0.5);
    pageLinks[pi].push({ rect: [x, yy - 2.5, x + w, yy + size * 0.72], uri: url });
    return w;
  };

  const MIN_Y = 56;
  const ensure = (space) => { if (y - space < MIN_Y) { addPage(); y = PAGE_H - M; } };

  const TEXT_X = M + 16 + 66;
  const ITEM_MAXW = PAGE_W - M - TEXT_X;

  // chips de link fluindo (quebram para nova linha); atualiza y
  function flowLinks(links, x0, maxW, size) {
    ensure(13);
    let lineX = x0;
    links.forEach((lk) => {
      const w = textW(lk.label, size);
      if (lineX > x0 && lineX + w > x0 + maxW) { y -= 12; ensure(12); lineX = x0; }
      linkLabel(lineX, y, lk.label, lk.url, size);
      lineX += w + 12;
    });
    y -= 13;
  }

  function renderItem(it) {
    const st = RISK[it.sev] || RISK.pendente;
    ensure(16);
    circle(M + 5, y - 3.4, 3.4, st.rgb);
    text(M + 16, y, st.label, 7.5, st.rgb, true);

    wrap(it.text, ITEM_MAXW, 10.5).forEach((ln, i) => {
      if (i > 0) ensure(13);
      text(TEXT_X, y, ln, 10.5, INK, false);
      y -= 13;
    });

    if (it.desc) {
      String(it.desc).split("\n").flatMap((d) => wrap(d, ITEM_MAXW, 9)).forEach((ln) => {
        ensure(11); text(TEXT_X, y + 1, ln, 9, MUTED, false); y -= 11;
      });
    }

    if (it.link) {
      ensure(13);
      linkLabel(TEXT_X, y, clipW(it.link.label || it.link.url, ITEM_MAXW, 9), it.link.url, 9);
      y -= 13;
    }

    if (it.cveLinks && it.cveLinks.length) flowLinks(it.cveLinks, TEXT_X, ITEM_MAXW, 9);

    y -= 5;
  }

  // -- header band --
  fillRect(0, PAGE_H - HEADER_H, PAGE_W, HEADER_H, ACCENT);
  text(M, PAGE_H - 34, "NavSec — Relatório de segurança", 18, WHITE, true);
  text(M, PAGE_H - 52, "Gerado em " + date, 9.5, WHITE, false);
  const chips = ["alto", "medio", "baixa", "ok"].filter((k) => counts[k] > 0)
                  .map((k) => ({ c: RISK[k].rgb, label: RISK[k].label + " " + counts[k] }));
  const chipW = (lab) => 12 + textW(lab, 7.5, true);
  const totalW = chips.reduce((a, c) => a + chipW(c.label) + 6, -6);
  let cx = PAGE_W - M - Math.max(totalW, 0);
  chips.forEach((c) => {
    const w = chipW(c.label);
    fillRect(cx, PAGE_H - 47, w, 19, c.c);
    text(cx + 6, PAGE_H - 41, c.label, 7.5, WHITE, true);
    cx += w + 6;
  });
  y = PAGE_H - HEADER_H - 26;

  // -- meta --
  text(M, y, "Página analisada", 8.5, MUTED, true); y -= 13;
  wrap(url, PAGE_W - 2 * M, 10).forEach((ln) => { text(M, y, ln, 10, INK, false); y -= 13; });
  y -= 4;
  text(M, y, "Fontes: OSV.dev · VirusTotal · AbuseIPDB · Security Headers", 9.5, MUTED, false);
  y -= 26;

  // -- sections --
  sections.forEach((sec) => {
    ensure(46);
    text(M, y, sec.title, 13, INK, true); y -= 7;
    line(M, y, PAGE_W - M, y, INK, 1.1); y -= 20;

    if (!sec.available) {
      const lines = wrap(sec.note, ITEM_MAXW, 10.5);
      ensure(Math.max(lines.length * 13, 16) + 6);
      circle(M + 5, y - 3.4, 3.4, RISK.pendente.rgb);
      text(M + 16, y, RISK.pendente.label, 7.5, RISK.pendente.rgb, true);
      lines.forEach((ln, i) => text(TEXT_X, y - i * 13, ln, 10.5, MUTED, false));
      y -= Math.max(lines.length * 13, 16) + 7 + 14;
      return;
    }

    sec.blocks.forEach((block) => {
      if (block.label) { ensure(20); text(M, y, block.label, 9.5, MUTED, true); y -= 15; }
      block.items.slice().sort((a, b) => ORDER.indexOf(a.sev) - ORDER.indexOf(b.sev)).forEach(renderItem);
      y -= 6;
    });
    if (sec.footnote) { ensure(16); text(M, y, sec.footnote, 8.5, MUTED, false); y -= 14; }
    y -= 10;
  });

  // -- footers --
  const N = pages.length;
  for (let p = 0; p < N; p++) {
    pi = p;
    line(M, 36, PAGE_W - M, 36, LINE, 0.5);
    text(M, 24, "NavSec — Relatório de segurança", 8, [0.6, 0.6, 0.6], false);
    const right = `pág. ${p + 1} / ${N}`;
    text(PAGE_W - M - textW(right, 8), 24, right, 8, [0.6, 0.6, 0.6], false);
  }

  // =============================================================
  // Objetos + xref — numeração dinâmica (páginas, conteúdo e anotações)
  // =============================================================
  const objs = [];
  objs[1] = "<< /Type /Catalog /Pages 2 0 R >>";
  objs[3] = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>";
  objs[4] = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>";

  let num = 5;
  const meta = [];
  for (let p = 0; p < N; p++) {
    const pageNum = num++, contentNum = num++;
    const annotNums = pageLinks[p].map(() => num++);
    meta.push({ pageNum, contentNum, annotNums, links: pageLinks[p], data: pages[p].join("\n") });
  }
  objs[2] = `<< /Type /Pages /Kids [${meta.map((m) => `${m.pageNum} 0 R`).join(" ")}] /Count ${N} >>`;
  meta.forEach((m) => {
    const annots = m.annotNums.length ? ` /Annots [${m.annotNums.map((n) => `${n} 0 R`).join(" ")}]` : "";
    objs[m.pageNum] = `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${PAGE_W} ${PAGE_H}] ` +
                      `/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >>${annots} /Contents ${m.contentNum} 0 R >>`;
    objs[m.contentNum] = `<< /Length ${m.data.length} >>\nstream\n${m.data}\nendstream`;
    m.links.forEach((lk, i) => {
      objs[m.annotNums[i]] = `<< /Type /Annot /Subtype /Link /Rect [${lk.rect.map(f).join(" ")}] ` +
                             `/Border [0 0 0] /A << /S /URI /URI (${escPdf(lk.uri)}) >> >>`;
    });
  });

  const maxObj = num - 1;
  let pdf = "%PDF-1.4\n";
  const offsets = [];
  for (let i = 1; i <= maxObj; i++) {
    offsets[i] = pdf.length;
    pdf += `${i} 0 obj\n${objs[i]}\nendobj\n`;
  }
  const xrefStart = pdf.length;
  const size = maxObj + 1;
  pdf += `xref\n0 ${size}\n0000000000 65535 f \n`;
  for (let i = 1; i <= maxObj; i++) pdf += String(offsets[i]).padStart(10, "0") + " 00000 n \n";
  pdf += `trailer\n<< /Size ${size} /Root 1 0 R >>\nstartxref\n${xrefStart}\n%%EOF`;
  return pdf;
}

function pdfBytes(pdf) {
  const bytes = new Uint8Array(pdf.length);
  for (let i = 0; i < pdf.length; i++) bytes[i] = pdf.charCodeAt(i) & 0xff;
  return bytes;
}

// =============================================================
// API pública — recebe o router.state inteiro
// =============================================================
export function downloadReport(state) {
  const blob = new Blob([pdfBytes(buildStyledPdf(state))], { type: "application/pdf" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = "relatorio-navsec.pdf";
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(link.href), 2000);
}

export { buildStyledPdf };
