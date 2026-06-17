// =============================================================
// report.js  -  Gera um PDF minimo (valido) com o resultado da
// coleta e dispara o download. Usa a analise real quando disponivel.
// =============================================================

function escapePdf(text) {
  return String(text).replace(/\\/g, "\\\\").replace(/\(/g, "\\(").replace(/\)/g, "\\)");
}

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

function buildLines(scan) {
  const date = new Date().toLocaleString("pt-BR");
  const lines = [
    "NavSec - Relatorio de coleta",
    "",
    `Pagina analisada: ${(scan && scan.url) || "-"}`,
    `Gerado em: ${date}`,
    "",
  ];

  const techs = (scan && scan.technologies) || [];
  if (!techs.length) {
    lines.push("Nenhuma tecnologia detectada (ou pagina nao analisada).");
  } else {
    const risco = { alto: "ALTO", medio: "MEDIO", ok: "OK", pendente: "?" };
    lines.push(`Tecnologias detectadas: ${techs.length}`, "");
    techs.forEach((t) => {
      const r = risco[t.risk] || "?";
      const cve = t.worst ? t.worst.displayId : (t.cveCount ? t.cveCount + " CVE" : "sem CVE");
      lines.push(`- ${t.name} ${t.version}  [${r}]  ${cve}`);
    });
  }
  lines.push("", "Fonte das CVEs: OSV.dev");
  return lines;
}

export function downloadReport(scan) {
  const pdf = buildPdf(buildLines(scan));
  const blob = new Blob([pdf], { type: "application/pdf" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = "relatorio-navsec.pdf";
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(link.href), 2000);
}
