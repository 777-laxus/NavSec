// =============================================================
// report.js  -  Gera um PDF minimo (valido) com o resumo da
// analise e dispara o download. Simula o relatorio do NavSec.
// =============================================================

import { pageUrl, summary, technologies, riskLabels } from "./stack/data.js";

function escapePdf(text) {
  return String(text).replace(/\\/g, "\\\\").replace(/\(/g, "\\(").replace(/\)/g, "\\)");
}

// Monta um PDF 1.4 simples com uma pagina e texto em Helvetica.
function buildPdf(lines) {
  const objects = [];
  objects.push("<< /Type /Catalog /Pages 2 0 R >>");
  objects.push("<< /Type /Pages /Kids [3 0 R] /Count 1 >>");
  objects.push(
    "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] " +
      "/Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>"
  );

  let stream = "BT\n/F1 14 Tf\n18 TL\n50 790 Td\n";
  lines.forEach((line, i) => {
    if (i > 0) stream += "T*\n";
    stream += `(${escapePdf(line)}) Tj\n`;
  });
  stream += "ET";
  objects.push(`<< /Length ${stream.length} >>\nstream\n${stream}\nendstream`);
  objects.push("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>");

  let pdf = "%PDF-1.4\n";
  const offsets = [];
  objects.forEach((body, i) => {
    offsets.push(pdf.length);
    pdf += `${i + 1} 0 obj\n${body}\nendobj\n`;
  });

  const xrefStart = pdf.length;
  const total = objects.length + 1;
  pdf += `xref\n0 ${total}\n0000000000 65535 f \n`;
  offsets.forEach((off) => {
    pdf += String(off).padStart(10, "0") + " 00000 n \n";
  });
  pdf += `trailer\n<< /Size ${total} /Root 1 0 R >>\nstartxref\n${xrefStart}\n%%EOF`;
  return pdf;
}

function buildLines() {
  const date = new Date().toLocaleString("pt-BR");
  const lines = [
    "NavSec - Relatorio de analise",
    "",
    `Pagina analisada: ${pageUrl}`,
    `Gerado em: ${date}`,
    "",
    `Resumo: ${summary.alto} Alto | ${summary.medio} Medio | ${summary.ok} OK`,
    "",
    "Tecnologias detectadas:",
  ];
  technologies.forEach((t) => {
    const cve = t.cveCount > 0 ? t.cve : "sem CVE conhecida";
    lines.push(`- ${t.name} ${t.version}  [${riskLabels[t.risk]}]  ${cve}`);
  });
  lines.push("");
  lines.push("Relatorio ilustrativo (versao academica do NavSec).");
  return lines;
}

export function downloadReport() {
  const pdf = buildPdf(buildLines());
  const blob = new Blob([pdf], { type: "application/pdf" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = "relatorio-navsec.pdf";
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(link.href), 2000);
}
