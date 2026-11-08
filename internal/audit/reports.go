package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"
)

const reportTemplate = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SecuBrain / Security Audit</title><style>
:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#0b0e12;color:#e6eaf0;font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;line-height:1.6}
main{max-width:920px;margin:0 auto;padding:64px 24px 96px}header{border-bottom:1px solid #252b33;padding-bottom:38px;margin-bottom:38px}
.kicker{color:#8f9aaa;font-size:11px;font-weight:600;letter-spacing:.16em;text-transform:uppercase}h1{font-size:clamp(38px,6vw,62px);letter-spacing:-.055em;line-height:1.1;margin:14px 0 10px;font-weight:650}h1 span{color:#8595a9}
h2{font-size:18px;font-weight:600;letter-spacing:-.015em;margin:48px 0 15px}h3{font-size:17px;margin:0 0 5px}.muted{color:#98a5b4}.small{font-size:12px}.meta{font-size:13px;word-break:break-word}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-top:30px}.metric{border:1px solid #2b323b;border-radius:8px;padding:16px;background:#11161d}.metric strong{display:block;font-size:29px;line-height:1.2}.metric span{font-size:12px;color:#aab4c1}
.finding{border:1px solid #2b323b;border-radius:9px;padding:20px;margin-bottom:13px;background:#11161c}.finding-top{display:flex;justify-content:space-between;gap:12px;align-items:start}.sev{font:600 10px ui-monospace,monospace;letter-spacing:.09em;border-radius:4px;padding:4px 8px;text-transform:uppercase;background:#242a33;color:#cbd4df}
.sev-high{color:#ff9b99;background:#392223}.sev-medium{color:#f8ca91;background:#3b3122}.sev-low{color:#a8c6f2;background:#222f42}.sev-info{color:#b4becb}
.finding p{font-size:13px;color:#c0cad6;margin:12px 0}.finding dl{display:grid;grid-template-columns:110px 1fr;gap:7px;font-size:12px;overflow-wrap:anywhere}.finding dt{color:#8a98a9}.finding dd{margin:0}.label{font-family:ui-monospace,monospace;color:#b7c4d1}
.note{border-left:2px solid #54677e;padding:3px 16px;color:#a9b5c4;font-size:13px}.footer{margin-top:55px;padding-top:22px;border-top:1px solid #252b33;color:#8a98a9;font-size:12px}ul{padding-left:21px}li{padding-bottom:6px}code{background:#1d2530;padding:2px 5px;border-radius:4px}
@media(max-width:540px){main{padding:36px 16px}.grid{grid-template-columns:repeat(2,1fr)}.finding dl{grid-template-columns:1fr;gap:2px}.finding dt{margin-top:7px}}
@media print{:root{color-scheme:light}body{background:white;color:#151515}.finding,.metric{background:white;border-color:#ccc}.muted,.finding p,.finding dd,.label{color:#333}.footer{color:#444}}
</style></head><body><main>
<header><div class="kicker">SECUBRAIN / AUTOMATED SECURITY AUDIT</div><h1>Security<span>.</span> Report</h1>
<div class="muted meta">Generated {{.FinishedAt.Format "2006-01-02 15:04:05 UTC"}} &nbsp; · &nbsp; Version {{.Version}}</div>
{{if .Path}}<div class="meta muted">Project: <code>{{.Path}}</code></div>{{end}}
{{if .URL}}<div class="meta muted">Target URL: <code>{{.URL}}</code></div>{{end}}
<div class="grid"><div class="metric"><strong>{{.Stats.High}}</strong><span>High</span></div><div class="metric"><strong>{{.Stats.Medium}}</strong><span>Medium</span></div><div class="metric"><strong>{{.Stats.Low}}</strong><span>Low</span></div><div class="metric"><strong>{{.Stats.Info}}</strong><span>Informational</span></div></div>
</header>
<div class="note">Automated indicators, not a penetration test. A finding may require manual validation; absence of findings does not establish security. No exploitation or brute-force testing was performed.</div>
{{if .Nmap}}<h2>01 / Nmap network discovery</h2>
<p class="muted small">Execution status: <strong>{{.Nmap.Status}}</strong> · Target: <code>{{.Nmap.Target}}</code> · Duration: {{.Nmap.DurationMS}} ms</p>
<p class="muted small">Mode: {{.Nmap.Mode}} · Open TCP ports observed: {{.Nmap.OpenTCPPorts}} · Version: {{.Nmap.Version}}</p>
<p class="note">Nmap is a separately installed third-party tool. Service detection is an estimate, not exploit validation.</p>{{end}}
<h2>02 / Findings</h2>
{{if .Findings}}{{range .Findings}}<article class="finding"><div class="finding-top"><h3>{{.Title}}</h3><span class="sev sev-{{.Severity}}">{{.Severity}}</span></div>
<div class="small muted">{{.ID}} / {{.Category}}</div><p>{{.Description}}</p>
<dl><dt>Location</dt><dd class="label">{{if .Location}}{{.Location}}{{if .Line}}:{{.Line}}{{end}}{{else}}—{{end}}</dd>
<dt>Evidence</dt><dd>{{.Evidence}}</dd><dt>Recommendation</dt><dd>{{.Recommendation}}</dd></dl></article>{{end}}{{else}}<p class="muted">No indicators detected by the enabled checks.</p>{{end}}
<h2>03 / Checks performed</h2><ul>{{range .Checks}}<li>{{.}}</li>{{end}}</ul>
<h2>04 / Execution notes</h2><p class="muted small">Files inspected: {{.Stats.FilesInspected}} · Bytes inspected: {{.Stats.BytesInspected}}</p>
{{if .Warnings}}<ul>{{range .Warnings}}<li>{{.}}</li>{{end}}</ul>{{else}}<p class="muted">No execution warnings.</p>{{end}}
<div class="footer">SECUBRAIN v{{.Version}} &nbsp;/&nbsp; Deterministic analysis &nbsp;/&nbsp; For authorized systems only</div>
</main></body></html>`

func WriteReports(dir string, r Report) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create report directory: %w", err)
	}
	raw, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "report.json"), append(raw, '\n'), 0600); err != nil {
		return err
	}
	templ, err := template.New("report").Parse(reportTemplate)
	if err != nil {
		return err
	}
	var html bytes.Buffer
	if err := templ.Execute(&html, r); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "report.html"), html.Bytes(), 0600); err != nil {
		return err
	}
	md := asMarkdown(r)
	if err := os.WriteFile(filepath.Join(dir, "report.md"), []byte(md), 0600); err != nil {
		return err
	}
	return nil
}

func cleanMD(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "`", "'")
	return s
}

func asMarkdown(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# SecuBrain / Security Audit\n\nGenerated: %s | Version: %s\n\n", r.FinishedAt.Format("2006-01-02 15:04 UTC"), r.Version)
	if r.Path != "" {
		fmt.Fprintf(&b, "**Project:** %s  \n", cleanMD(r.Path))
	}
	if r.URL != "" {
		fmt.Fprintf(&b, "**URL:** %s  \n", cleanMD(r.URL))
	}
	fmt.Fprintf(&b, "\n**Indicators:** %d high · %d medium · %d low · %d informational\n\n", r.Stats.High, r.Stats.Medium, r.Stats.Low, r.Stats.Info)
	b.WriteString("> Automated indicators only, not a penetration test. No exploitation or brute force was performed.\n\n")
	if r.Nmap != nil {
		fmt.Fprintf(&b, "## Nmap network discovery\n\n- Status: %s\n- Target: %s\n- Version: %s\n- Mode: %s\n- Open TCP ports: %d\n- Duration: %d ms\n\n", cleanMD(r.Nmap.Status), cleanMD(r.Nmap.Target), cleanMD(r.Nmap.Version), cleanMD(r.Nmap.Mode), r.Nmap.OpenTCPPorts, r.Nmap.DurationMS)
	}
	b.WriteString("## Findings\n\n")
	if len(r.Findings) == 0 {
		b.WriteString("No indicators detected by the enabled checks.\n\n")
	}
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "### %s — %s (%s)\n\n", f.ID, cleanMD(f.Title), f.Severity)
		if f.Location != "" {
			fmt.Fprintf(&b, "- **Location:** %s", cleanMD(f.Location))
			if f.Line != 0 {
				fmt.Fprintf(&b, ":%d", f.Line)
			}
			b.WriteByte('\n')
		}
		fmt.Fprintf(&b, "- **Category:** %s\n- **Description:** %s\n- **Evidence:** %s\n- **Recommendation:** %s\n\n", cleanMD(f.Category), cleanMD(f.Description), cleanMD(f.Evidence), cleanMD(f.Recommendation))
	}
	b.WriteString("## Checks performed\n\n")
	for _, c := range r.Checks {
		fmt.Fprintf(&b, "- %s\n", cleanMD(c))
	}
	fmt.Fprintf(&b, "\n## Execution notes\n\n- Files inspected: %d\n- Bytes inspected: %d\n", r.Stats.FilesInspected, r.Stats.BytesInspected)
	for _, w := range r.Warnings {
		fmt.Fprintf(&b, "- Warning: %s\n", cleanMD(w))
	}
	return b.String()
}
