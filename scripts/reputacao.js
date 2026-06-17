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

  // 1. Captura a aba ativa
  let currentUrl = "https://exemplo.com.br"; 
  
  if (typeof chrome !== "undefined" && chrome.tabs) {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tabs.length > 0 && tabs[0].url) {
      currentUrl = tabs[0].url;
    }
  }

  urlEl.textContent = currentUrl;

  let domain = "";
  try {
    domain = new URL(currentUrl).hostname;
  } catch (e) {
    domain = currentUrl;
  }

  // 2. Análise de HTTPS
  if (currentUrl.startsWith("https://")) {
    httpsEl.innerHTML = `<span class="badge badge--ok">Seguro</span> Conexão encriptada.`;
  } else {
    httpsEl.innerHTML = `<span class="badge badge--alto">Inseguro</span> Tráfego em texto claro.`;
  }

  // Ignora chamadas de API se for um ambiente local
  if (domain === "localhost" || domain === "127.0.0.1") {
    vtEl.innerHTML = `<span class="badge badge--medio">N/A</span> Ambiente local`;
    abuseEl.innerHTML = `<span class="badge badge--medio">N/A</span> Ambiente local`;
  } else {
    // 3. Consulta Real ao VirusTotal
    checkVirusTotal(domain, vtEl);

    // 4. Consulta Real ao AbuseIPDB
    checkAbuseIPDB(domain, abuseEl);
  }

  // 5. Avaliação Real de Security Headers
  checkRealHeaders(currentUrl, headersListEl);
}

/**
 * Consulta a API v3 do VirusTotal
 */
async function checkVirusTotal(domain, containerEl) {
  if (!VT_API_KEY || VT_API_KEY === "") {
    containerEl.innerHTML = `<span class="badge badge--medio">Aviso</span> Chave de API ausente.`;
    return;
  }

  try {
    const response = await fetch(`https://www.virustotal.com/api/v3/domains/${domain}`, {
      method: "GET",
      headers: { "x-apikey": VT_API_KEY }
    });

    if (!response.ok) throw new Error(`Erro HTTP: ${response.status}`);
    
    const data = await response.json();
    const stats = data.data.attributes.last_analysis_stats;
    const maliciousCount = stats.malicious;
    const totalCount = stats.malicious + stats.undetected + stats.harmless + stats.suspicious;

    if (maliciousCount > 0) {
      containerEl.innerHTML = `<span class="badge badge--alto">${maliciousCount} / ${totalCount}</span> Motores detetaram ameaças!`;
    } else {
      containerEl.innerHTML = `<span class="badge badge--ok">Limpo</span> 0 / ${totalCount} motores reportaram problemas.`;
    }
  } catch (error) {
    console.error("[NavSec] Erro no VirusTotal:", error);
    containerEl.innerHTML = `<span class="badge badge--alto">Erro</span> Falha ao consultar VT.`;
  }
}

/**
 * Consulta a API v2 do AbuseIPDB
 */
async function checkAbuseIPDB(domain, containerEl) {
  if (!ABUSE_API_KEY || ABUSE_API_KEY === "") {
    containerEl.innerHTML = `<span class="badge badge--medio">Aviso</span> Chave de API ausente.`;
    return;
  }

  try {
    const dnsResponse = await fetch(`https://dns.google/resolve?name=${domain}&type=A`);
    const dnsData = await dnsResponse.json();
    
    if (!dnsData.Answer || dnsData.Answer.length === 0) {
      throw new Error("Não foi possível resolver o IP do domínio.");
    }
    
    const ipAddress = dnsData.Answer.find(a => a.type === 1).data;

    const abuseResponse = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ipAddress}&maxAgeInDays=90`, {
      method: "GET",
      headers: {
        "Accept": "application/json",
        "Key": ABUSE_API_KEY
      }
    });

    if (!abuseResponse.ok) throw new Error(`Erro HTTP: ${abuseResponse.status}`);

    const abuseData = await abuseResponse.json();
    const score = abuseData.data.abuseConfidenceScore;

    if (score > 0) {
      containerEl.innerHTML = `<span class="badge badge--alto">${score}%</span> Confiança de Abuso.`;
    } else {
      containerEl.innerHTML = `<span class="badge badge--ok">${score}%</span> IP limpo na base.`;
    }
  } catch (error) {
    console.error("[NavSec] Erro no AbuseIPDB:", error);
    containerEl.innerHTML = `<span class="badge badge--alto">Erro</span> Falha ao consultar IP.`;
  }
}

/**
 * Lê e valida os Cabeçalhos reais do site
 */
async function checkRealHeaders(url, containerEl) {
  // Estado inicial: Assumimos o pior cenário (todos ausentes)
  let securityHeaders = [
    { name: "Content-Security-Policy (CSP)", status: "alto", desc: "Ausente. Risco severo de XSS e injeção de dados." },
    { name: "Strict-Transport-Security (HSTS)", status: "alto", desc: "Ausente. Risco de Downgrade para HTTP (MitM)." },
    { name: "X-Frame-Options", status: "medio", desc: "Ausente. Permite incorporação, risco de Clickjacking." },
    { name: "X-Content-Type-Options", status: "medio", desc: "Ausente. Risco de ataques via MIME-sniffing." }
  ];

  containerEl.innerHTML = `<div style="padding: 10px; text-align: center; font-size: 13px; color: var(--muted);">A ler cabeçalhos reais do site...</div>`;

  try {
    // Baixamos apenas os cabeçalhos (sem baixar o HTML da página toda) para ser muito rápido
    const response = await fetch(url, { method: "HEAD" });
    const headers = response.headers;

    // 1. Validação do CSP
    if (headers.get("Content-Security-Policy")) {
      securityHeaders[0] = { name: "Content-Security-Policy (CSP)", status: "ok", desc: "Configurado. Protege contra injeções de scripts maliciosos." };
    }

    // 2. Validação do HSTS
    if (headers.get("Strict-Transport-Security")) {
      securityHeaders[1] = { name: "Strict-Transport-Security (HSTS)", status: "ok", desc: "Configurado. Força navegadores a usar apenas HTTPS." };
    }

    // 3. Validação do X-Frame-Options
    const xfo = headers.get("X-Frame-Options");
    if (xfo && (xfo.toUpperCase() === "DENY" || xfo.toUpperCase() === "SAMEORIGIN")) {
      securityHeaders[2] = { name: "X-Frame-Options", status: "ok", desc: `Configurado (${xfo}). Protege o site contra Clickjacking.` };
    }

    // 4. Validação do X-Content-Type-Options
    const xcto = headers.get("X-Content-Type-Options");
    if (xcto && xcto.toLowerCase() === "nosniff") {
      securityHeaders[3] = { name: "X-Content-Type-Options", status: "ok", desc: "Configurado (nosniff). Bloqueia tentativas de MIME-sniffing." };
    }
  } catch (error) {
    console.warn("[NavSec] Não foi possível ler os cabeçalhos devido a restrições CORS da página.");
    // Em caso de bloqueio, mantemos os de risco para alertar o usuário, 
    // mas a requisição pode falhar em sites extremamente restritos.
  }

  // Renderização Visual no HTML
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
      </span>
    `;
    
    containerEl.appendChild(card);
  });
}