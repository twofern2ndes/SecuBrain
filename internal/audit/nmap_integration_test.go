package audit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func fakeNmap(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "fake-nmap")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", bin, "./testdata/fakenmap")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build fake nmap: %v\n%s", err, out)
	}
	return bin
}

func TestNmapIntegrationNoNetwork(t *testing.T) {
	bin := fakeNmap(t)
	r := Report{Findings: []Finding{}, Warnings: []string{}, Checks: []string{}}
	scanNmap(context.Background(), Config{URL: "http://127.0.0.1:9876", Nmap: true, Authorized: true, NmapBinary: bin}, &r)
	if r.Nmap == nil || r.Nmap.Status != "completed" || r.Nmap.OpenTCPPorts != 1 {
		t.Fatalf("Nmap results: %+v / %+v", r.Nmap, r.Warnings)
	}
	if r.Findings[0].Severity != "info" || r.Findings[0].Location != "127.0.0.1:443" || !strings.Contains(r.Findings[0].Evidence, "Fixture Web 1.2.3") {
		t.Fatalf("unexpected finding: %+v", r.Findings)
	}
	if strings.Contains(r.Findings[0].Evidence, "open") { /* 'open' here is not a vulnerability claim */
	}
	if err := WriteReports(t.TempDir(), r); err != nil {
		t.Fatal(err)
	}
}

func TestNmapExplicitMissingPath(t *testing.T) {
	r := Report{Findings: []Finding{}, Warnings: []string{}}
	scanNmap(context.Background(), Config{URL: "https://127.0.0.1", NmapBinary: filepath.Join(t.TempDir(), "absent-nmap")}, &r)
	if r.Nmap == nil || r.Nmap.Status != "skipped" || len(r.Warnings) == 0 {
		t.Fatalf("expected clear skipped state: %+v", r)
	}
}

func TestNmapArgsAreFixedAndCannotInjectFlags(t *testing.T) {
	for _, host := range []string{"example.com", "127.0.0.1"} {
		args := nmapArgs(host)
		if len(args) != 16 || args[len(args)-1] != host {
			t.Fatalf("unexpected args: %v", args)
		}
		for _, arg := range args[:len(args)-1] {
			if strings.Contains(arg, ";") || strings.Contains(arg, "&&") {
				t.Fatalf("shell syntax: %q", arg)
			}
		}
	}
	if _, err := parseNmapOutput([]byte("not xml"), "127.0.0.1"); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestNoLeaksFromNmapRawOutput(t *testing.T) {
	xml := []byte(`<nmaprun><host><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https" product="&lt;script&gt;"/></port></ports></host></nmaprun>`)
	items, err := parseNmapOutput(xml, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	r := Report{Findings: items}
	dir := t.TempDir()
	if err := WriteReports(dir, r); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "report.html"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "<script>") {
		t.Fatal("Nmap service label injected HTML")
	}
}

func TestEndToEndAuthorizedWebAndFakeNmap(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "HEAD" {
			t.Errorf("unexpected method %s", r.Method)
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	fake := fakeNmap(t)
	out := t.TempDir()
	report, err := Run(context.Background(), Config{URL: server.URL, Authorized: true, Nmap: true, NmapBinary: fake, Output: out}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if report.Nmap == nil || report.Nmap.Status != "completed" || report.Nmap.OpenTCPPorts != 1 {
		t.Fatalf("expected fake Nmap service: %+v", report.Nmap)
	}
	for _, name := range []string{"report.html", "report.json", "report.md"} {
		b, err := os.ReadFile(filepath.Join(out, name))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), "127.0.0.1") {
			t.Fatalf("missing target in %s", name)
		}
	}
}

func TestNmapOutputLimit(t *testing.T) {
	var buffer cappedBuffer
	buffer.max = 4
	if _, err := buffer.Write([]byte("abcd")); err != nil {
		t.Fatal(err)
	}
	if _, err := buffer.Write([]byte("e")); err == nil {
		t.Fatal("expected bounded XML output")
	}
}
