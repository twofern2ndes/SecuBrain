package audit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLocalAuditRedactsCredentialsInAllReports(t *testing.T) {
	project := t.TempDir()
	output := filepath.Join(t.TempDir(), "out")
	token := "ghp_" + strings.Repeat("A", 36)
	secret := "SuperSecretValue12345"
	data := "token = \"" + token + "\"\npassword = \"" + secret + "\"\n-----BEGIN PRIVATE KEY-----\n"
	if err := os.WriteFile(filepath.Join(project, "config.py"), []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, ".env"), []byte("SAMPLE=1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(project, "node_modules"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "node_modules", "hidden.py"), []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	report, err := Run(context.Background(), Config{Path: project, Output: output}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if report.Stats.High < 2 || report.Stats.Medium < 2 {
		t.Fatalf("expected issues, got %+v", report.Stats)
	}
	if report.Stats.FilesInspected != 2 {
		t.Fatalf("expected skip node_modules: %+v", report.Stats)
	}
	for _, name := range []string{"report.json", "report.html", "report.md"} {
		raw, err := os.ReadFile(filepath.Join(output, name))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), token) || strings.Contains(string(raw), secret) {
			t.Fatalf("secret leaked in %s", name)
		}
	}
}

func TestAuthorizedWebHeaderAudit(t *testing.T) {
	called := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		if r.Method != "HEAD" {
			t.Errorf("unexpected HTTP method %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	_, err := Run(context.Background(), Config{URL: server.URL, Output: t.TempDir()}, nil)
	if err == nil || !strings.Contains(err.Error(), "--authorized") {
		t.Fatalf("expected authorization error, got %v", err)
	}
	report, err := Run(context.Background(), Config{URL: server.URL, Authorized: true, Output: t.TempDir()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if called != 1 {
		t.Fatalf("expected one HEAD request, got %d", called)
	}
	if len(report.Findings) < 2 {
		t.Fatalf("expected missing header advisories, got %+v", report.Findings)
	}
}

func TestWebRedirectNotFollowed(t *testing.T) {
	originCalls, destCalls := 0, 0
	dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { destCalls++ }))
	defer dest.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originCalls++
		http.Redirect(w, r, dest.URL, http.StatusFound)
	}))
	defer origin.Close()
	report, err := Run(context.Background(), Config{URL: origin.URL, Authorized: true, Output: t.TempDir()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if originCalls != 1 || destCalls != 0 {
		t.Fatalf("redirect followed: origin=%d dest=%d", originCalls, destCalls)
	}
	if len(report.Warnings) == 0 {
		t.Fatal("expected warning on redirect")
	}
}

func TestURLValidation(t *testing.T) {
	cases := []Config{
		{URL: "https://example.test/?token=example", Authorized: true},
		{URL: "https://user:pass@example.test/", Authorized: true},
		{URL: "file:///etc/passwd", Authorized: true},
		{URL: "https://example.test/#frag", Authorized: true},
		{URL: "https://example.test", Nmap: true},
	}
	for _, c := range cases {
		if err := c.validate(); err == nil {
			t.Fatalf("expected invalid config: %+v", c)
		}
	}
}

func TestParseNmapOutput(t *testing.T) {
	xmlText := []byte(`<?xml version="1.0"?><nmaprun><host><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port><port protocol="tcp" portid="22"><state state="closed"/></port></ports></host></nmaprun>`)
	items := parseNmapOutput(xmlText, "example.test")
	if len(items) != 1 || items[0].Severity != "info" || items[0].Location != "example.test:443" {
		t.Fatalf("unexpected port findings: %+v", items)
	}
	noOpen := parseNmapOutput([]byte(`<nmaprun><host><ports></ports></host></nmaprun>`), "example.test")
	if noOpen == nil {
		t.Fatal("valid XML with zero ports must not be treated as parse failure")
	}
}

func TestHTMLTemplateEscapesFileNames(t *testing.T) {
	r := Report{Findings: []Finding{{Title: "<script>alert(1)</script>", Severity: "info"}}, Warnings: []string{}, Checks: []string{}}
	dir := t.TempDir()
	if err := WriteReports(dir, r); err != nil {
		t.Fatal(err)
	}
	html, err := os.ReadFile(filepath.Join(dir, "report.html"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(html), "<script>alert(1)</script>") {
		t.Fatal("unsafe unescaped HTML")
	}
}
