package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strconv"
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
{{if .Target}}<div class="meta muted">Nmap target: <code>{{.Target}}</code></div>{{end}}
<div class="grid"><div class="metric"><strong>{{.Stats.High}}</strong><span>High</span></div><div class="metric"><strong>{{.Stats.Medium}}</strong><span>Medium</span></div><div class="metric"><strong>{{.Stats.Low}}</strong><span>Low</span></div><div class="metric"><strong>{{.Stats.Info}}</strong><span>Informational</span></div></div>
</header>
<div class="note">Automated indicators, not a penetration test. A finding may require manual validation; absence of findings does not establish security. No exploitation or brute-force testing was performed.</div>
{{if .Nmap}}<h2>01 / Nmap network inventory</h2>
<p class="muted small">Status: <strong>{{.Nmap.Status}}</strong> · Profile: {{.Nmap.Profile}} · Target: <code>{{.Nmap.Target}}</code> · Duration: {{.Nmap.DurationMS}} ms</p>
<p class="muted small">Mode: {{.Nmap.Mode}} · Nmap: {{.Nmap.Version}} · Hosts up: {{.Nmap.HostsUp}} · Open TCP: {{.Nmap.OpenTCPPorts}} · Open UDP: {{.Nmap.OpenUDPPorts}}</p>
<p class="note">Services, product versions, OS guesses, and script data are Nmap observations, not confirmed vulnerabilities. Full structured port results are available in report.json.</p>
{{range .Nmap.Hosts}}
<h3>Host — {{.Status}}</h3><p class="small muted">Addresses: {{range .Addresses}}{{.}} {{end}} · Hostnames: {{range .Hostnames}}{{.}} {{end}} · Uptime (s): {{.UptimeSeconds}}</p>
{{if .OSMatches}}<p class="small muted">OS guesses: {{range .OSMatches}}{{.Name}} ({{.Accuracy}}%) &nbsp; {{end}}</p>{{end}}
{{if .ExtraPortStates}}<p class="small muted">Aggregated states: {{range $key,$value := .ExtraPortStates}}{{$key}}={{$value}} &nbsp; {{end}}</p>{{end}}
<table style="width:100%;border-collapse:collapse;font-size:12px;table-layout:fixed"><thead><tr><th align="left">Protocol / Port</th><th align="left">State</th><th align="left">Service</th><th align="left">Product / Version</th></tr></thead><tbody>
{{range visiblePorts .Ports}}<tr style="border-bottom:1px solid #30343c"><td>{{.Protocol}}/{{.Number}}</td><td>{{.State}}</td><td>{{.Service}}</td><td style="overflow-wrap:anywhere">{{.Product}} {{.Version}} {{.ExtraInfo}}</td></tr>{{else}}<tr><td colspan="4" class="muted">No open or open|filtered ports observed.</td></tr>{{end}}
</tbody></table>
{{range visiblePorts .Ports}}{{if or .CPE .Scripts}}<details style="margin:9px 0;padding:7px 0;border-bottom:1px solid #30343c"><summary class="small">{{.Protocol}}/{{.Number}} — detailed metadata</summary>
<p class="small muted">Reason: {{.Reason}} · Service source: {{.Method}} · Confidence: {{.Confidence}}/10 · Tunnel: {{.Tunnel}}</p>
{{if .CPE}}<p class="small muted">CPE: {{range .CPE}}<code>{{.}}</code> {{end}}</p>{{end}}
{{range .Scripts}}<p class="small"><strong>NSE {{.ID}}</strong>: {{.Output}}</p>{{end}}
</details>{{end}}{{end}}
{{if gt (len .Ports) 500}}<p class="small muted">For very large results, HTML shows at most 500 reported open/open|filtered ports. See report.json for every parsed port and NSE script output.</p>{{end}}
{{end}}
{{end}}
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
	templ, err := template.New("report").Funcs(template.FuncMap{"visiblePorts": visiblePorts}).Parse(reportTemplate)
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

func visiblePorts(ports []NmapPort) []NmapPort {
	selected := make([]NmapPort, 0)
	for _, p := range ports {
		if p.State == "open" || p.State == "open|filtered" {
			selected = append(selected, p)
		}
		if len(selected) >= 500 {
			break
		}
	}
	return selected
}

func cleanMD(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "`", "'")
	s = strings.ReplaceAll(s, "|", "\\|")
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
	if r.Target != "" {
		fmt.Fprintf(&b, "**Nmap target:** %s  \n", cleanMD(r.Target))
	}
	fmt.Fprintf(&b, "\n**Indicators:** %d high · %d medium · %d low · %d informational\n\n", r.Stats.High, r.Stats.Medium, r.Stats.Low, r.Stats.Info)
	b.WriteString("> Automated indicators only, not a penetration test. No exploitation or brute force was performed.\n\n")
	if r.Nmap != nil {
		n := r.Nmap
		fmt.Fprintf(&b, "## Nmap network inventory\n\n- Status: %s\n- Target: %s\n- Profile: %s\n- Mode: %s\n- Version: %s\n- Hosts up: %d\n- Open TCP ports: %d\n- Open UDP ports: %d\n- Duration: %d ms\n\n", cleanMD(n.Status), cleanMD(n.Target), cleanMD(n.Profile), cleanMD(n.Mode), cleanMD(n.Version), n.HostsUp, n.OpenTCPPorts, n.OpenUDPPorts, n.DurationMS)
		for i, h := range n.Hosts {
			fmt.Fprintf(&b, "### Host %d — %s\n\n", i+1, cleanMD(h.Status))
			if len(h.Addresses) > 0 {
				fmt.Fprintf(&b, "- Addresses: %s\n", cleanMD(strings.Join(h.Addresses, ", ")))
			}
			if len(h.Hostnames) > 0 {
				fmt.Fprintf(&b, "- Hostnames: %s\n", cleanMD(strings.Join(h.Hostnames, ", ")))
			}
			if len(h.OSMatches) > 0 {
				fmt.Fprintf(&b, "- OS estimate: %s (%d%%)\n", cleanMD(h.OSMatches[0].Name), h.OSMatches[0].Accuracy)
			}
			if len(h.ExtraPortStates) > 0 {
				for state, count := range h.ExtraPortStates {
					fmt.Fprintf(&b, "- %s (aggregated): %d ports\n", cleanMD(state), count)
				}
			}
			b.WriteString("\n| Protocol | Port | State | Service | Product / Version |\n|---|---:|---|---|---|\n")
			entries := visiblePorts(h.Ports)
			for _, port := range entries {
				fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n", cleanMD(port.Protocol), strconv.Itoa(port.Number), cleanMD(port.State), cleanMD(port.Service), cleanMD(strings.TrimSpace(port.Product+" "+port.Version+" "+port.ExtraInfo)))
			}
			if len(entries) == 0 {
				b.WriteString("| — | — | — | No open ports observed | — |\n")
			}
			if len(entries) >= 500 {
				b.WriteString("\nPort display limited to 500 rows. Full parsed inventory and NSE output: `report.json`.\n")
			}
			b.WriteString("\n")
		}
		b.WriteString("> Port/service/OS observations are not proof of a vulnerability.\n\n")
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
