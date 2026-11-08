"""Regenerate deterministic documentation SVGs from pre-verified fixture output.

These diagrams are formatted renderings, not original browser or OS screenshots.
No external fonts or images are embedded.
"""
from pathlib import Path
from html import escape
import json

BASE = Path(__file__).resolve().parent
ASSETS = BASE / 'assets'
ASSETS.mkdir(parents=True, exist_ok=True)

def text(x, y, content, size=24, color='#cad5e1', weight=400, family='mono'):
    family_name = 'ui-monospace, SFMono-Regular, Consolas, Liberation Mono, monospace' if family=='mono' else 'Inter, Segoe UI, Arial, sans-serif'
    return f'<text x="{x}" y="{y}" fill="{color}" font-family="{family_name}" font-size="{size}" font-weight="{weight}">{escape(content)}</text>'

def shell_frame(title, subtitle, rows, footer, file):
    W,H=1440,710
    pieces=[f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" role="img" aria-label="{escape(title)}">',
        '<rect width="1440" height="710" rx="22" fill="#090d12"/>',
        '<rect x="24" y="24" width="1392" height="662" rx="16" fill="#111820" stroke="#334254" stroke-width="2"/>',
        '<path d="M24 96H1416" stroke="#2d3845" stroke-width="2"/>',
        '<circle cx="65" cy="60" r="8" fill="#a8595d"/><circle cx="91" cy="60" r="8" fill="#a18959"/><circle cx="117" cy="60" r="8" fill="#5b987d"/>',
        text(150,67,'SECUBRAIN / '+title.upper(),20,'#d2dde9',600),
        text(58,143,subtitle,20,'#7f8fa4',400),]
    y=208
    for content, color in rows:
        pieces.append(text(58,y,content,25,color))
        y+=43
    pieces += ['<path d="M58 634H1382" stroke="#303f50"/>',text(58,667,footer,17,'#8292a5'),'</svg>']
    (ASSETS / file).write_text('\n'.join(pieces),encoding='utf-8')

shell_frame('Local audit','VERIFIED LOCAL EXECUTION  /  GO 1.23  /  SYNTHETIC FIXTURE',[
    ('$ ./secubrain scan --path ./examples/demo-project --out ./secubrain-reports','#e3e9f1'),
    ('[>] Inspecting project files...','#9cacbd'),
    ('[>] Writing HTML, Markdown and JSON reports...','#9cacbd'),
    ('','#9cacbd'),
    ('[OK] Inspected 2 files. Findings: 0 high / 2 medium / 0 low / 0 info','#9ed4b3'),
    ('[OK] Report: .../secubrain-reports/report.html','#9ed4b3'),
    ('[OK] JSON:   .../secubrain-reports/report.json','#9ed4b3'),
    ('[OK] Markdown: .../secubrain-reports/report.md','#9ed4b3'),
], 'Source: actual SecuBrain CLI output; absolute paths shortened for documentation.', 'cli-demo.svg')

shell_frame('Test suite','GO TEST -COUNT=1 -V ./...   /   8 PASSING TESTS',[
    ('=== RUN   TestLocalAuditRedactsCredentialsInAllReports','#b9c5d3'),
    ('--- PASS: TestLocalAuditRedactsCredentialsInAllReports','#9ed4b3'),
    ('=== RUN   TestAuthorizedWebHeaderAudit','#b9c5d3'),
    ('--- PASS: TestAuthorizedWebHeaderAudit','#9ed4b3'),
    ('=== RUN   TestWebRedirectNotFollowed / TestURLValidation','#b9c5d3'),
    ('--- PASS: both tests','#9ed4b3'),
    ('=== RUN   Nmap XML / HTML escaping / CLI parsing tests','#b9c5d3'),
    ('--- PASS: all remaining tests     TOTAL: 8 PASS','#9ed4b3'),
], 'Summary formatted from real Go test output; names combined for readability.', 'test-suite.svg')

r=json.loads((BASE/'samples/demo-report.json').read_text())
W,H=1440,780
p=[f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" role="img" aria-label="SecuBrain generated report overview">',
   '<rect width="1440" height="780" rx="22" fill="#090d12"/>',
   '<rect x="32" y="28" width="1376" height="724" rx="14" fill="#111820" stroke="#334254" stroke-width="2"/>',
   text(72,87,'SECUBRAIN / AUTOMATED AUDIT REPORT',19,'#8494a9',600),
   text(72,165,'Security. Report',61,'#f1f4f8',650,'sans'),
   text(73,208,'v0.1.0  ·  synthetic demo-project  ·  no exploitation performed',19,'#8b99ad',400,'sans')]
for i,(title,num,color) in enumerate([('HIGH',r['stats']['high'],'#b8c4d2'),('MEDIUM',r['stats']['medium'],'#f0cb88'),('LOW',r['stats']['low'],'#b8c4d2'),('INFO',r['stats']['info'],'#b8c4d2')]):
    x=72+i*330
    p.extend([f'<rect x="{x}" y="252" width="307" height="138" rx="10" fill="#17212b" stroke="#2f4052"/>',text(x+24,310,str(num),48,color,650,'sans'),text(x+25,353,title,18,'#96a6ba',600)])
p += [text(72,458,'01  /  FINDINGS',22,'#dce6f2',600),
    '<rect x="72" y="482" width="1295" height="109" rx="10" fill="#18222d" stroke="#344556"/>',
    text(95,525,'Potential hardcoded credential',24,'#ecf2f8',600,'sans'),
    text(95,560,'app.py:4  •  Credential-style assignment detected; value redacted',19,'#a6b6c8',400),
    '<rect x="72" y="605" width="1295" height="94" rx="10" fill="#18222d" stroke="#344556"/>',
    text(95,644,'Potential hardcoded credential',24,'#ecf2f8',600,'sans'),
    text(95,677,'app.py:5  •  Credential-style assignment detected; value redacted',19,'#a6b6c8',400),
    text(73,737,'Visualization of real synthetic-fixture JSON output; not a production scan.',16,'#8090a2'),'</svg>']
(ASSETS/'report-overview.svg').write_text('\n'.join(p),encoding='utf-8')
print('Assets:',[(f.name,f.stat().st_size) for f in ASSETS.glob('*.svg')])
