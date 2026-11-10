const fs = require('fs');
const f = process.argv[2];
if (!f) { console.log('Pakai: node ringkas.js <file.json>'); process.exit(1); }
const d = JSON.parse(fs.readFileSync(f, 'utf8'));
const vulns = d.vulnerabilities || [];
const uniq = new Map();
vulns.forEach(v => uniq.set(v.id + '|' + v.packageName + '@' + v.version, v));
const list = [...uniq.values()];
const sev = { critical: 0, high: 0, medium: 0, low: 0 };
list.forEach(v => sev[v.severity]++);
console.log('\n== TOTAL KERENTANAN (unik):', list.length);
console.log(sev);
const rank = { critical: 4, high: 3, medium: 2, low: 1 };
const sorted = [...list].sort((a, b) => rank[b.severity] - rank[a.severity] || (b.cvssScore || 0) - (a.cvssScore || 0));
const pk = new Map();
sorted.forEach(v => { const k = v.packageName + '@' + v.version; if (!pk.has(k)) pk.set(k, v); });
console.log('\n== 3 PACKAGE PALING RENTAN');
[...pk.values()].slice(0, 3).forEach(v => console.log(`- ${v.packageName} ${v.version} | ${v.severity} | versi aman: ${(v.fixedIn || []).join(', ') || '(belum ada)'}`));
console.log('\n== KANDIDAT 3 CVE UNTUK TABEL D.1.3');
const seen = new Set(); let n = 0;
for (const v of sorted) {
  if (!['critical', 'high'].includes(v.severity) || seen.has(v.packageName)) continue;
  seen.add(v.packageName); n++;
  const cve = (v.identifiers && v.identifiers.CVE || []).join(', ') || '(tidak ada CVE; pakai ' + v.id + ')';
  console.log(`\n#${n}`);
  console.log('Snyk ID         :', v.id);
  console.log('CVE ID          :', cve);
  console.log('Package@versi   :', v.packageName + '@' + v.version);
  console.log('CVSS/Severity   :', v.cvssScore, '/', v.severity);
  console.log('Vector (CVSS)   :', v.CVSSv3 || '-');
  console.log('Exploit         :', v.exploit || 'Not Defined');
  console.log('Judul           :', v.title);
  console.log('Versi diperbaiki:', (v.fixedIn || []).join(', ') || '(belum ada)');
  console.log('Detail          : https://security.snyk.io/vuln/' + v.id);
  if (n >= 3) break;
}