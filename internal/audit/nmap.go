package audit

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Nmap is deliberately a separate, user-installed dependency. SecuBrain never
// redistributes Nmap or Npcap, and never invokes a shell to construct a scan.
// The only permitted scan is a single-host, bounded TCP connect + light service
// discovery using explicitly enumerated arguments. There is no NSE, -A, -O,
// UDP scan, credential testing, brute force, script, or exploit execution.
const NmapMode = "TCP connect; 100 common ports; light service detection; low rate"

type NmapStatus struct {
	Available bool   `json:"available"`
	Binary    string `json:"binary,omitempty"`
	Version   string `json:"version,omitempty"`
	Source    string `json:"source,omitempty"`
}

type NmapSummary struct {
	Status       string `json:"status"`
	Target       string `json:"target"`
	Mode         string `json:"mode"`
	Version      string `json:"version,omitempty"`
	DurationMS   int64  `json:"duration_ms"`
	OpenTCPPorts int    `json:"open_tcp_ports"`
	BinarySource string `json:"binary_source,omitempty"`
}

// A subprocess is never permitted to emit unbounded XML into process memory.
type cappedBuffer struct {
	bytes.Buffer
	max int
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.max {
		return 0, errors.New("Nmap XML output limit exceeded")
	}
	return b.Buffer.Write(p)
}

type nmapXML struct {
	XMLName xml.Name `xml:"nmaprun"`
	Hosts   []struct {
		Ports struct {
			Ports []struct {
				Protocol string `xml:"protocol,attr"`
				PortID   string `xml:"portid,attr"`
				State    struct {
					State string `xml:"state,attr"`
				} `xml:"state"`
				Service struct {
					Name    string `xml:"name,attr"`
					Product string `xml:"product,attr"`
					Version string `xml:"version,attr"`
					Tunnel  string `xml:"tunnel,attr"`
				} `xml:"service"`
			} `xml:"port"`
		} `xml:"ports"`
	} `xml:"host"`
}

func parseNmapOutput(raw []byte, host string) ([]Finding, error) {
	var data nmapXML
	if err := xml.Unmarshal(raw, &data); err != nil || data.XMLName.Local != "nmaprun" {
		return nil, errors.New("invalid Nmap XML output")
	}
	items := []Finding{}
	for _, h := range data.Hosts {
		for _, p := range h.Ports.Ports {
			if p.State.State != "open" || p.Protocol != "tcp" {
				continue
			}
			if p.PortID == "" {
				continue
			}
			service := sanitizedService(p.Service.Name)
			if service == "" {
				service = "unknown"
			}
			product := sanitizedService(p.Service.Product)
			version := sanitizedService(p.Service.Version)
			tunnel := sanitizedService(p.Service.Tunnel)
			details := service
			if tunnel != "" {
				details += " / " + tunnel
			}
			if product != "" {
				details += " / " + product
			}
			if version != "" {
				details += " " + version
			}
			location := host + ":" + p.PortID
			items = append(items, newFinding("info", "network-discovery", "Open TCP port "+p.PortID+" ("+service+")",
				"A TCP port responded as open during bounded service discovery. An open port alone is not a vulnerability.",
				"Nmap TCP connect; reported service: "+details, location, 0,
				"Confirm the service is expected and restrict access through firewall and service configuration."))
		}
	}
	return items, nil
}

func sanitizedService(s string) string {
	s = strings.TrimSpace(strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, s))
	if len(s) > 96 {
		return s[:96] + "..."
	}
	return s
}

// LocateNmap locates a pre-installed binary. An explicit override is never
// silently replaced by another executable: bad overrides fail clearly.
func LocateNmap(override string) (NmapStatus, error) {
	candidates := []struct{ path, source string }{}
	if override != "" {
		candidates = append(candidates, struct{ path, source string }{override, "explicit override"})
	} else if env := os.Getenv("SECUBRAIN_NMAP_PATH"); env != "" {
		candidates = append(candidates, struct{ path, source string }{env, "environment"})
	} else {
		candidates = append(candidates, struct{ path, source string }{"nmap", "PATH"})
		if runtime.GOOS == "windows" {
			for _, root := range []string{os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)"), os.Getenv("LOCALAPPDATA")} {
				if root != "" {
					candidates = append(candidates, struct{ path, source string }{filepath.Join(root, "Nmap", "nmap.exe"), "standard installation"})
				}
			}
		}
	}
	for _, candidate := range candidates {
		resolved, err := exec.LookPath(candidate.path)
		if err != nil {
			continue
		}
		return NmapStatus{Available: true, Binary: resolved, Source: candidate.source}, nil
	}
	if override != "" {
		return NmapStatus{}, fmt.Errorf("Nmap not found at the specified --nmap-bin path")
	}
	if os.Getenv("SECUBRAIN_NMAP_PATH") != "" {
		return NmapStatus{}, fmt.Errorf("Nmap not found at SECUBRAIN_NMAP_PATH")
	}
	return NmapStatus{}, fmt.Errorf("Nmap not installed or not found; get it independently from https://nmap.org/download.html")
}

func DetectNmap(parent context.Context, override string) (NmapStatus, error) {
	status, err := LocateNmap(override)
	if err != nil {
		return status, err
	}
	ctx, cancel := context.WithTimeout(parent, 8*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, status.Binary, "--version").Output()
	if err != nil {
		return status, fmt.Errorf("could not query Nmap version: %w", err)
	}
	line := strings.SplitN(string(out), "\n", 2)[0]
	status.Version = sanitizedService(line)
	return status, nil
}

// nmapArgs is a deliberately fixed, non-configurable allowlist. A raw target
// value can never be interpreted as an extra flag because validation rejects
// leading hyphens and the target is passed as one exec argv element.
func nmapArgs(host string) []string {
	return []string{"-sT", "-sV", "--version-light", "-Pn", "-F", "-T2", "--max-rate", "25", "--max-retries", "1", "--host-timeout", "80s", "--open", "-oX", "-", host}
}

func scanNmap(parent context.Context, cfg Config, r *Report) {
	u, _ := url.Parse(cfg.URL)
	host := u.Hostname()
	info := &NmapSummary{Status: "skipped", Target: host, Mode: NmapMode}
	r.Nmap = info
	status, err := DetectNmap(parent, cfg.NmapBinary)
	if err != nil {
		r.Warnings = append(r.Warnings, err.Error()+"; network discovery skipped")
		return
	}
	info.Version, info.BinarySource = status.Version, status.Source
	ctx, cancel := context.WithTimeout(parent, 95*time.Second)
	defer cancel()
	start := time.Now()
	cmd := exec.CommandContext(ctx, status.Binary, nmapArgs(host)...)
	// The limited output is parsed as XML and not stored in reports: Nmap and
	// external services may include untrusted/raw values in their output.
	buffer := &cappedBuffer{max: 4 << 20}
	cmd.Stdout = buffer
	cmd.Stderr = io.Discard
	err = cmd.Run()
	info.DurationMS = time.Since(start).Milliseconds()
	if err != nil {
		info.Status = "failed"
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			r.Warnings = append(r.Warnings, "Nmap timed out; no network discoveries recorded")
		} else {
			r.Warnings = append(r.Warnings, "Nmap failed; no network discoveries recorded (check target, permissions and local Nmap installation)")
		}
		return
	}
	items, err := parseNmapOutput(buffer.Bytes(), host)
	if err != nil {
		info.Status = "failed"
		r.Warnings = append(r.Warnings, "Nmap returned invalid XML; network findings omitted")
		return
	}
	info.Status = "completed"
	info.OpenTCPPorts = len(items)
	r.Findings = append(r.Findings, items...)
}
