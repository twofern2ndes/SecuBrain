package audit

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

func fakeNmap(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "fake-nmap")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", bin, "./testdata/fakenmap")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build fake Nmap: %v\n%s", err, out)
	}
	return bin
}
func TestProfileArguments(t *testing.T) {
	for _, tc := range []struct {
		profile   string
		portArg   string
		intensity string
	}{{"quick", "-F", "2"}, {"standard", "", "5"}, {"full", "-p-", "7"}} {
		cfg := Config{NmapProfile: tc.profile}
		args := nmapArgs("127.0.0.1", cfg)
		if args[len(args)-1] != "127.0.0.1" || !slices.Contains(args, "-sT") || !slices.Contains(args, "-sV") || !slices.Contains(args, "-oX") {
			t.Errorf("%s missing required flags: %v", tc.profile, args)
		}
		if tc.portArg != "" && !slices.Contains(args, tc.portArg) {
			t.Errorf("%s port profile: %v", tc.profile, args)
		}
		if !slices.Contains(args, tc.intensity) {
			t.Errorf("%s intensity: %v", tc.profile, args)
		}
		for _, a := range args {
			if strings.Contains(a, ";") || strings.Contains(a, "&&") {
				t.Fatalf("shell tokens in argv: %q", a)
			}
		}
	}
	args := nmapArgs("127.0.0.1", Config{NmapProfile: "full", NmapUDP: true, NmapOS: true, NmapScripts: true, NmapTimeout: time.Minute})
	for _, item := range []string{"-p", "T:1-65535,U:1-1024", "-sU", "-O", "--script", "default", "60s"} {
		if !slices.Contains(args, item) {
			t.Errorf("missing %s: %v", item, args)
		}
	}
	if i := slices.Index(args, "-p"); i < 0 || args[i+1] != "T:1-65535,U:1-1024" {
		t.Fatalf("port option not adjacent: %v", args)
	}
}
func TestNmapInventoryStructured(t *testing.T) {
	binary := fakeNmap(t)
	out := t.TempDir()
	report, err := Run(context.Background(), Config{Target: "127.0.0.1", Authorized: true, Nmap: true, NmapBinary: binary, NmapProfile: "full", NmapUDP: true, Output: out}, nil)
	if err != nil {
		t.Fatal(err)
	}
	n := report.Nmap
	if n == nil || n.Status != "completed" || n.Profile != "full" || n.HostsUp != 1 || n.OpenTCPPorts != 1 || n.OpenUDPPorts != 1 {
		t.Fatalf("inventory: %+v", n)
	}
	if len(n.Hosts) != 1 || len(n.Hosts[0].Ports) != 3 || len(n.Hosts[0].OSMatches) != 1 || n.Hosts[0].ExtraPortStates["filtered"] != 98 {
		t.Fatalf("host inventory: %+v", n.Hosts)
	}
	p := n.Hosts[0].Ports[0]
	if p.Number != 22 || n.Hosts[0].Ports[1].Product != "Fixture Web" || len(n.Hosts[0].Ports[1].Scripts) != 1 {
		t.Fatalf("port attributes: %+v", n.Hosts[0].Ports)
	}
	if report.Stats.Info != 2 {
		t.Fatalf("informational findings: %+v", report.Stats)
	}
	for _, name := range []string{"report.json", "report.html", "report.md"} {
		content, readErr := os.ReadFile(filepath.Join(out, name))
		if readErr != nil {
			t.Fatal(readErr)
		}
		if !strings.Contains(string(content), "Fixture Web") {
			t.Errorf("missing service in %s", name)
		}
		if name == "report.html" && strings.Contains(string(content), "<script> HTML") {
			t.Fatal("unescaped Nmap output")
		}
	}
	data, err := os.ReadFile(filepath.Join(out, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var decoded Report
	if err = json.Unmarshal(data, &decoded); err != nil || decoded.Nmap.Hosts[0].Ports[1].Scripts[0].ID != "http-title" {
		t.Fatalf("JSON data lost: %v / %+v", err, decoded.Nmap)
	}
}
func TestNmapUnavailableReturnsNonZeroAndReport(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing-nmap")
	report, err := Run(context.Background(), Config{Target: "127.0.0.1", Authorized: true, Nmap: true, NmapBinary: missing, Output: dir}, nil)
	if err == nil || report.Nmap.Status != "skipped" || len(report.Warnings) == 0 {
		t.Fatalf("expected explicit failure: %v %+v", err, report.Nmap)
	}
	if _, err := os.Stat(filepath.Join(dir, "report.json")); err != nil {
		t.Fatal("failure report missing", err)
	}
}
func TestNmapScopeValidation(t *testing.T) {
	invalid := []Config{
		{Target: "127.0.0.1", Nmap: true},
		{Target: "1.2.3.4/24", Authorized: true, Nmap: true},
		{Target: "-iL", Authorized: true, Nmap: true},
		{Target: "https://foo.test", Authorized: true, Nmap: true},
		{Target: "foo.test;echo", Authorized: true, Nmap: true},
		{Target: "foo.test", URL: "https://bar.test", Authorized: true, Nmap: true},
		{Target: "foo.test", Authorized: true, Nmap: true, NmapProfile: "everything"},
		{Target: "foo.test", Authorized: true, Nmap: true, NmapTimeout: 10 * time.Second},
		{Target: "foo.test", Authorized: true},
	}
	for _, c := range invalid {
		if err := c.validate(); err == nil {
			t.Errorf("invalid scope accepted: %+v", c)
		}
	}
	for _, target := range []string{"127.0.0.1", "::1", "example.org"} {
		c := Config{Target: target, Authorized: true, Nmap: true}
		if err := c.validate(); err != nil {
			t.Errorf("valid target %s rejected: %v", target, err)
		}
	}
}
func TestNmapIPv6Arguments(t *testing.T) {
	args := nmapArgs("::1", Config{NmapProfile: "quick"})
	if !slices.Contains(args, "-6") || args[len(args)-1] != "::1" {
		t.Fatalf("Nmap IPv6 mode missing: %v", args)
	}
}
func TestNmapParserRejectsMalformedAndMultipleHosts(t *testing.T) {
	for _, raw := range []string{"invalid", "<foo />", "<nmaprun><host/><host/></nmaprun>"} {
		if _, err := parseNmapInventory([]byte(raw)); err == nil {
			t.Errorf("accepted %s", raw)
		}
	}
	hosts, err := parseNmapInventory([]byte(`<nmaprun><host><ports><port protocol="tcp" portid="-1"><state state="open"/></port><port protocol="tcp" portid="70000"/><port protocol="tcp" portid="80"><state state="open"/></port><port protocol="tcp" portid="80"><state state="open"/></port></ports></host></nmaprun>`))
	if err != nil || len(hosts[0].Ports) != 1 {
		t.Fatalf("invalid or duplicate port retained: %v %v", hosts, err)
	}
}
func TestNmapOutputLimit(t *testing.T) {
	b := cappedBuffer{max: 4}
	if _, err := b.Write([]byte("abcd")); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Write([]byte("e")); err == nil {
		t.Fatal("output cap not enforced")
	}
}
