/**
 * Lógica da Tela de Reputação
 * Consultas reais via API (VirusTotal, AbuseIPDB) e leitura real de Cabeçalhos (Security Headers).
 */

// Chaves reais inseridas para a apresentação
const VT_API_KEY = "5c57386806dee79b62f44aa147ad5e7900aba1c757da38626ba04f62447ecdbc";
const ABUSE_API_KEY = "1d2eff66642a54d5b8c6bba6a034304b3a80563c529a32f0b8d746b86cdde6357e368e6ef7fc2724";

export async function init(container, ctx) {
  const urlEl = container.querySelector("#rep-url");
  const httpsEl = container.querySelector("#rep-https");
  const vtEl = container.querySelector("#rep-vt");
  const abuseEl = container.querySelector("#rep-abuse");
  const headersListEl = container.querySelector("#rep-headers-list");

  let currentUrl = "https://exemplo.com.br";
  if (typeof chrome !== "undefined" && chrome.tabs) {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tabs.length > 0 && tabs[0].url) currentUrl = tabs[0].url;
  }
  urlEl.textContent = currentUrl;

  let domain = "";
  try { domain = new URL(currentUrl).hostname; } catch (e) { domain = currentUrl; }

  // + NavSec: acumulador lido pelo report.js
  const rep = (ctx.state.reputation = {
    url: currentUrl, domain, https: null, virustotal: null, abuseipdb: null, headers: [],
  });

  if (currentUrl.startsWith("https://")) {
    httpsEl.innerHTML = `<span class="badge badge--ok">Seguro</span> Conexão criptografada.`;
    rep.https = { status: "ok", label: "Conexão criptografada (TLS)." };               // +
  } else {
    httpsEl.innerHTML = `<span class="badge badge--alto">Inseguro</span> Tráfego em texto claro.`;
    rep.https = { status: "alto", label: "Tráfego em texto claro (sem HTTPS)." };   // +
  }

  if (domain === "localhost" || domain === "127.0.0.1") {
    vtEl.innerHTML = `<span class="badge badge--medio">N/A</span> Ambiente local`;
    abuseEl.innerHTML = `<span class="badge badge--medio">N/A</span> Ambiente local`;
    rep.virustotal = { status: "pendente", label: "Ambiente local (não consultado)." }; // +
    rep.abuseipdb  = { status: "pendente", label: "Ambiente local (não consultado)." }; // +
  } else {
    checkVirusTotal(domain, vtEl, rep);   // + rep
    checkAbuseIPDB(domain, abuseEl, rep); // + rep
  }

  checkRealHeaders(currentUrl, headersListEl, rep); // + rep
}
/**
 * Consulta a API v3 do VirusTotal
 */

async function checkVirusTotal(domain, containerEl, rep) {
  if (!VT_API_KEY || VT_API_KEY === "") {
    containerEl.innerHTML = `<span class="badge badge--medio">Aviso</span> Chave de API ausente.`;
    if (rep) rep.virustotal = { status: "pendente", label: "Chave de API ausente." }; // +
    return;
  }

  try {
    const response = await fetch(`https://www.virustotal.com/api/v3/domains/${domain}`, {
      method: "GET", headers: { "x-apikey": VT_API_KEY }
    });
    if (!response.ok) throw new Error(`Erro HTTP: ${response.status}`);

    const data = await response.json();
    const stats = data.data.attributes.last_analysis_stats;
    const maliciousCount = stats.malicious;
    const totalCount = stats.malicious + stats.undetected + stats.harmless + stats.suspicious;
    const vtLink = `https://www.virustotal.com/gui/domain/${domain}/detection`;

    if (maliciousCount > 0) {
      containerEl.innerHTML = `
        <div style="margin-bottom: 8px;">
          <span class="badge badge--alto">${maliciousCount} / ${totalCount}</span> Motores detectaram ameaças!
        </div>
        <p style="font-size: 0.85em; color: #666; margin: 0 0 8px 0; line-height: 1.4;">
          O domínio foi sinalizado por fornecedores de segurança como malicioso ou suspeito em atividades de phishing ou malware.
        </p>
        <a href="${vtLink}" target="_blank" rel="noopener noreferrer" style="font-size: 0.85em; font-weight: bold; color: #3b5998; text-decoration: none;">
          Ver relatório no VirusTotal &rarr;
        </a>`;
      if (rep) rep.virustotal = {                                                    // +
        status: "alto", url: vtLink,
        label: `${maliciousCount}/${totalCount} motores detectaram ameaças.`,
        desc: "Sinalizado por fornecedores de segurança (phishing/malware).",
      };
    } else {
      containerEl.innerHTML = `
        <div style="margin-bottom: 8px;">
          <span class="badge badge--ok">Limpo</span> 0 / ${totalCount} motores reportaram problemas.
        </div>
        <p style="font-size: 0.85em; color: #666; margin: 0 0 8px 0; line-height: 1.4;">
          Nenhum motor de segurança detectou ameaças conhecidas associadas a este domínio no momento.
        </p>
        <a href="${vtLink}" target="_blank" rel="noopener noreferrer" style="font-size: 0.85em; font-weight: bold; color: #3b5998; text-decoration: none;">
          Ver relatório no VirusTotal &rarr;
        </a>`;
      if (rep) rep.virustotal = {                                                    // +
        status: "ok", url: vtLink,
        label: `Limpo (0/${totalCount} motores).`,
        desc: "Nenhuma ameaça conhecida associada a este domínio no momento.",
      };
    }
  } catch (error) {
    console.error("[NavSec] Erro no VirusTotal:", error);
    containerEl.innerHTML = `<span class="badge badge--alto">Erro</span> Falha ao consultar VT.`;
    if (rep) rep.virustotal = { status: "pendente", label: "Falha ao consultar o VirusTotal." }; // +
  }
}
/**
 * Consulta a API v2 do AbuseIPDB
 */
async function checkAbuseIPDB(domain, containerEl, rep) {
  if (!ABUSE_API_KEY || ABUSE_API_KEY === "") {
    containerEl.innerHTML = `<span class="badge badge--medio">Aviso</span> Chave de API ausente.`;
    if (rep) rep.abuseipdb = { status: "pendente", label: "Chave de API ausente." }; // +
    return;
  }

  try {
    const dnsResponse = await fetch(`https://dns.google/resolve?name=${domain}&type=A`);
    const dnsData = await dnsResponse.json();
    if (!dnsData.Answer || dnsData.Answer.length === 0) throw new Error("Não foi possível resolver o IP do domínio.");
    const ipAddress = dnsData.Answer.find(a => a.type === 1).data;

    const abuseResponse = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ipAddress}&maxAgeInDays=90`, {
      method: "GET", headers: { "Accept": "application/json", "Key": ABUSE_API_KEY }
    });
    if (!abuseResponse.ok) throw new Error(`Erro HTTP: ${abuseResponse.status}`);

    const abuseData = await abuseResponse.json();
    const score = abuseData.data.abuseConfidenceScore;
    const abuseLink = `https://www.abuseipdb.com/check/${ipAddress}`;

    if (score > 0) {
      containerEl.innerHTML = `
        <div style="margin-bottom: 8px;">
          <span class="badge badge--alto">${score}%</span> Confiança de Abuso.
        </div>
        <p style="font-size: 0.85em; color: #666; margin: 0 0 8px 0; line-height: 1.4;">
          O IP associado a este domínio (<strong>${ipAddress}</strong>) possui um histórico recente de atividades maliciosas reportadas (como spam, hacking ou DDoS).
        </p>
        <a href="${abuseLink}" target="_blank" rel="noopener noreferrer" style="font-size: 0.85em; font-weight: bold; color: #3b5998; text-decoration: none;">
          Ver relatório no AbuseIPDB &rarr;
        </a>`;
      if (rep) rep.abuseipdb = {                                                      // +
        status: "alto", url: abuseLink, ip: ipAddress,
        label: `${score}% de confiança de abuso — IP ${ipAddress}.`,
        desc: "Histórico recente de atividades maliciosas reportadas (spam, hacking ou DDoS).",
      };
    } else {
      containerEl.innerHTML = `
        <div style="margin-bottom: 8px;">
          <span class="badge badge--ok">${score}%</span> IP limpo na base.
        </div>
        <p style="font-size: 0.85em; color: #666; margin: 0 0 8px 0; line-height: 1.4;">
          O IP associado a este domínio (<strong>${ipAddress}</strong>) não possui relatórios recentes de abuso ou atividade maliciosa.
        </p>
        <a href="${abuseLink}" target="_blank" rel="noopener noreferrer" style="font-size: 0.85em; font-weight: bold; color: #3b5998; text-decoration: none;">
          Ver relatório no AbuseIPDB &rarr;
        </a>`;
      if (rep) rep.abuseipdb = {                                                      // +
        status: "ok", url: abuseLink, ip: ipAddress,
        label: `IP limpo na base (${score}%) — IP ${ipAddress}.`,
        desc: "Sem relatórios recentes de abuso ou atividade maliciosa.",
      };
    }
  } catch (error) {
    console.error("[NavSec] Erro no AbuseIPDB:", error);
    containerEl.innerHTML = `<span class="badge badge--alto">Erro</span> Falha ao consultar IP.`;
    if (rep) rep.abuseipdb = { status: "pendente", label: "Falha ao consultar o IP." }; // +
  }
}
/**
 * Lê e valida os Cabeçalhos reais do site
 */

async function checkRealHeaders(url, containerEl, rep) {
  let securityHeaders = [
    { name: "Content-Security-Policy (CSP)", status: "alto", desc: "Ausente. Risco severo de XSS e injeção de dados." },
    { name: "Strict-Transport-Security (HSTS)", status: "alto", desc: "Ausente. Risco de Downgrade para HTTP (MitM)." },
    { name: "X-Frame-Options", status: "medio", desc: "Ausente. Permite incorporação, risco de Clickjacking." },
    { name: "X-Content-Type-Options", status: "medio", desc: "Ausente. Risco de ataques via MIME-sniffing." }
  ];

  containerEl.innerHTML = `<div style="padding: 10px; text-align: center; font-size: 13px; color: var(--muted);">Lendo os cabeçalhos do site…</div>`;

  try {
    const response = await fetch(url, { method: "HEAD" });
    const headers = response.headers;

    if (headers.get("Content-Security-Policy")) {
      securityHeaders[0] = { name: "Content-Security-Policy (CSP)", status: "ok", desc: "Configurado. Protege contra injeções de scripts maliciosos." };
    }
    if (headers.get("Strict-Transport-Security")) {
      securityHeaders[1] = { name: "Strict-Transport-Security (HSTS)", status: "ok", desc: "Configurado. Força navegadores a usar apenas HTTPS." };
    }
    const xfo = headers.get("X-Frame-Options");
    if (xfo && (xfo.toUpperCase() === "DENY" || xfo.toUpperCase() === "SAMEORIGIN")) {
      securityHeaders[2] = { name: "X-Frame-Options", status: "ok", desc: `Configurado (${xfo}). Protege o site contra Clickjacking.` };
    }
    const xcto = headers.get("X-Content-Type-Options");
    if (xcto && xcto.toLowerCase() === "nosniff") {
      securityHeaders[3] = { name: "X-Content-Type-Options", status: "ok", desc: "Configurado (nosniff). Bloqueia tentativas de MIME-sniffing." };
    }
  } catch (error) {
    console.warn("[NavSec] Não foi possível ler os cabeçalhos devido a restrições CORS da página.");
  }

  if (rep) rep.headers = securityHeaders; // + NavSec: persiste para o relatório

  containerEl.innerHTML = "";
  securityHeaders.forEach(header => {
    const card = document.createElement("div");
    card.className = "tech-card";
    card.style.cursor = "default";
    const riskLabel = header.status === "ok" ? "OK" : (header.status === "alto" ? "ALTO" : "MÉDIO");
    card.innerHTML = `
      <span class="tech-card__main">
        <span class="tech-card__name">${header.name}</span>
        <span class="tech-card__version" style="white-space: normal; margin-top: 4px; line-height: 1.4;">${header.desc}</span>
      </span>
      <span class="tech-card__meta">
        <span class="badge badge--${header.status}">${riskLabel}</span>
      </span>`;
    containerEl.appendChild(card);
  });
}
