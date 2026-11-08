"""Generate 0.2 dark monochrome SVG figures from command output and stage descriptions.

The CLI text is captured by executing the local compiled program; the Nmap
fixture output is generated through a *separate* local fake executable.
The installer figure is a DOCUMENTED FLOW diagram, not a Windows screenshot.
"""
from __future__ import annotations
import html
import os
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "docs" / "assets"
ASSETS.mkdir(parents=True, exist_ok=True)
BIN = ROOT / "bin" / "secubrain"


def capture(*args: str, inp: str | None = None) -> str:
    if not BIN.is_file():
        raise RuntimeError("Build the local CLI first: go build -o bin/secubrain ./cmd/secubrain")
    p = subprocess.run([str(BIN), *args], input=inp, text=True, capture_output=True, env={**os.environ, "SECUBRAIN_PLAIN": "1"}, check=False)
    return (p.stdout + p.stderr).strip()


def svg_terminal(title: str, text: str, width: int = 1080) -> str:
    lines = text.splitlines()
    line_h = 26
    height = max(330, 120 + line_h * len(lines))
    content = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-label="{html.escape(title)}">',
               '<rect width="100%" height="100%" fill="#0b0f15" rx="15"/>',
               '<rect x="1" y="1" width="1078" height="%d" fill="none" stroke="#303945" rx="14"/>'%(height-2),
               '<path d="M0 55 H1080" stroke="#303945"/>',
               '<circle cx="26" cy="28" r="6" fill="#7f6870"/><circle cx="48" cy="28" r="6" fill="#8d8567"/><circle cx="70" cy="28" r="6" fill="#5e817b"/>',
               f'<text x="100" y="34" fill="#9facbd" font-size="14" font-family="DejaVu Sans Mono,Consolas,monospace">{html.escape(title)}</text>']
    for i,line in enumerate(lines):
        if not line.strip():continue
        if len(line)>108: line=line[:105]+"..."
        y=86+i*line_h
        color="#c9d3df"
        if line.lstrip().startswith(('✓','[OK]')):color="#9bdbb9"
        elif line.lstrip().startswith(('!','[!]')):color="#f2c88e"
        elif line.lstrip().startswith(('·','$','>')):color="#89aaca"
        elif 'SECUBRAIN' in line or 'AUDIT / COMPLETE' in line: color="#edf1f8"
        content.append(f'<text x="35" y="{y}" fill="{color}" xml:space="preserve" font-size="16" font-family="DejaVu Sans Mono,Consolas,monospace">{html.escape(line)}</text>')
    content.append('</svg>')
    return '\n'.join(content)+'\n'


def main() -> None:
    terminal = capture(inp='doctor\nversion\nexit\n')
    (ASSETS/'terminal-v02.svg').write_text(svg_terminal('SECUBRAIN / INTERACTIVE CLI / v0.2.0', terminal),encoding='utf-8')
    class FixtureHandler(BaseHTTPRequestHandler):
        def do_HEAD(self):
            self.send_response(200)
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.end_headers()
        def log_message(self, *_):
            return
    server = ThreadingHTTPServer(('127.0.0.1', 0), FixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        fixture = capture('scan','--url',f'http://127.0.0.1:{server.server_port}', '--authorized','--nmap','--nmap-bin',str(ROOT/'bin'/'fake-nmap'), '--out',str(ROOT/'dist'/'fixture-report'))
    finally:
        server.shutdown()
        server.server_close()
    fixture = 'OFFLINE TEST FIXTURE / FAKE NMAP / NOT A LIVE SCAN\n\n'+fixture
    (ASSETS/'nmap-fixture-v02.svg').write_text(svg_terminal('SECUBRAIN / NMAP PARSER TEST DOUBLE / v0.2.0', fixture),encoding='utf-8')
    stages=[('01','WELCOME','SecuBrain v0.2.0 / publisher details'),('02','AGREEMENT','Read complete terms; Accept or Decline'),('03','OPTIONS','Destination / desktop shortcut / user PATH'),('04','NMAP','Separate official download; not bundled'),('05','INSTALL','Real Windows Setup progress and file copy'),('06','COMPLETE','Start Menu shortcut / CLI doctor / uninstall')]
    parts=['<svg xmlns="http://www.w3.org/2000/svg" width="1080" height="525" viewBox="0 0 1080 525" role="img" aria-label="Documented SecuBrain installer wizard flow">','<rect width="100%" height="100%" rx="14" fill="#0c1016"/>','<text x="45" y="60" fill="#e8eef5" font-family="DejaVu Sans,Arial" font-size="27" font-weight="bold">WINDOWS SETUP / INSTALLATION FLOW</text>','<text x="45" y="88" fill="#93a5b8" font-family="DejaVu Sans,Arial" font-size="14">Documentation diagram · Inno Setup wizard · Nmap/Npcap separate</text>']
    for i,(num,title,description) in enumerate(stages):
        c=i%2;r=i//2;x=45+c*500;y=125+r*124
        parts += [f'<rect x="{x}" y="{y}" width="473" height="105" rx="8" fill="#151d27" stroke="#334153"/>',f'<text x="{x+22}" y="{y+35}" fill="#91b2d4" font-family="DejaVu Sans Mono,Consolas,monospace" font-size="18">{num} / {title}</text>',f'<text x="{x+22}" y="{y+67}" fill="#bac6d4" font-family="DejaVu Sans,Arial" font-size="13">{html.escape(description)}</text>']
    parts.append('</svg>')
    (ASSETS/'installer-flow-v02.svg').write_text('\n'.join(parts)+'\n',encoding='utf-8')
    print('Generated three SVG assets based on real CLI output, fake process output, and documented installer flow.')

if __name__ == '__main__': main()
