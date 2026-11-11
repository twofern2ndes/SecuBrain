package audit

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

// SecuBrain interoperates with a user-installed Nmap. It never redistributes
// Nmap or Npcap. Targets are one explicit IP address or DNS name per scan.
// Arguments are constructed as argv, never passed through a shell.
const nmapMaxXML = 24 << 20

// NmapStatus is a diagnostic, not a certification of the external executable.
type NmapStatus struct {
	Available bool   `json:"available"`
	Binary    string `json:"binary,omitempty"`
	Version   string `json:"version,omitempty"`
	Source    string `json:"source,omitempty"`
}

type NmapPort struct {
	Protocol   string       `json:"protocol"`
	Number     int          `json:"number"`
	State      string       `json:"state"`
	Reason     string       `json:"reason,omitempty"`
	Service    string       `json:"service,omitempty"`
	Product    string       `json:"product,omitempty"`
	Version    string       `json:"version,omitempty"`
	ExtraInfo  string       `json:"extra_info,omitempty"`
	Tunnel     string       `json:"tunnel,omitempty"`
	Method     string       `json:"method,omitempty"`
	Confidence int          `json:"confidence,omitempty"`
	CPE        []string     `json:"cpe,omitempty"`
	Scripts    []NmapScript `json:"scripts,omitempty"`
}

type NmapScript struct {
	ID     string `json:"id"`
	Output string `json:"output,omitempty"`
}

type NmapHost struct {
	Status          string         `json:"status"`
	Reason          string         `json:"reason,omitempty"`
	Addresses       []string       `json:"addresses,omitempty"`
	Hostnames       []string       `json:"hostnames,omitempty"`
	OSMatches       []NmapOSMatch  `json:"os_matches,omitempty"`
	Ports           []NmapPort     `json:"ports"`
	ExtraPortStates map[string]int `json:"extra_port_states,omitempty"`
	UptimeSeconds   int64          `json:"uptime_seconds,omitempty"`
}

type NmapOSMatch struct {
	Name     string `json:"name"`
	Accuracy int    `json:"accuracy"`
}

type NmapSummary struct {
	Status       string     `json:"status"`
	Target       string     `json:"target"`
	Profile      string     `json:"profile"`
	Mode         string     `json:"mode"`
	Version      string     `json:"version,omitempty"`
	DurationMS   int64      `json:"duration_ms"`
	OpenTCPPorts int        `json:"open_tcp_ports"`
	OpenUDPPorts int        `json:"open_udp_ports"`
	HostsUp      int        `json:"hosts_up"`
	BinarySource string     `json:"binary_source,omitempty"`
	Hosts        []NmapHost `json:"hosts"`
}

type cappedBuffer struct {
	bytes.Buffer
	max int
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.max {
		return 0, errors.New("Nmap output limit exceeded")
	}
	return b.Buffer.Write(p)
}

type nmapXML struct {
	XMLName xml.Name `xml:"nmaprun"`
	Hosts   []struct {
		Status struct {
			State  string `xml:"state,attr"`
			Reason string `xml:"reason,attr"`
		} `xml:"status"`
		Addresses []struct {
			Address string `xml:"addr,attr"`
			Type    string `xml:"addrtype,attr"`
		} `xml:"address"`
		Hostnames []struct {
			Name string `xml:"name,attr"`
		} `xml:"hostnames>hostname"`
		Uptime struct {
			Seconds string `xml:"seconds,attr"`
		} `xml:"uptime"`
		OS struct {
			Matches []struct {
				Name     string `xml:"name,attr"`
				Accuracy string `xml:"accuracy,attr"`
			} `xml:"osmatch"`
		} `xml:"os"`
		Ports struct {
			Extra []struct {
				State string `xml:"state,attr"`
				Count string `xml:"count,attr"`
			} `xml:"extraports"`
			Ports []struct {
				Protocol string `xml:"protocol,attr"`
				PortID   string `xml:"portid,attr"`
				State    struct {
					State  string `xml:"state,attr"`
					Reason string `xml:"reason,attr"`
				} `xml:"state"`
				Service struct {
					Name       string   `xml:"name,attr"`
					Product    string   `xml:"product,attr"`
					Version    string   `xml:"version,attr"`
					ExtraInfo  string   `xml:"extrainfo,attr"`
					Tunnel     string   `xml:"tunnel,attr"`
					Method     string   `xml:"method,attr"`
					Confidence string   `xml:"conf,attr"`
					CPE        []string `xml:"cpe"`
				} `xml:"service"`
				Scripts []struct {
					ID     string `xml:"id,attr"`
					Output string `xml:"output,attr"`
				} `xml:"script"`
			} `xml:"port"`
		} `xml:"ports"`
	} `xml:"host"`
}

func cleanNmapText(s string, max int) string {
	s = strings.TrimSpace(strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			if r == '\n' || r == '\t' {
				return ' '
			}
			return -1
		}
		return r
	}, s))
	if len(s) > max {
		s = strings.ToValidUTF8(s[:max], "") + "..."
	}
	return s
}
func sanitizedService(s string) string { return cleanNmapText(s, 96) }

func parseNmapInventory(raw []byte) ([]NmapHost, error) {
	var data nmapXML
	if len(raw) > nmapMaxXML {
		return nil, errors.New("Nmap XML output exceeds size limit")
	}
	if err := xml.Unmarshal(raw, &data); err != nil || data.XMLName.Local != "nmaprun" {
		return nil, errors.New("invalid Nmap XML output")
	}
	hosts := make([]NmapHost, 0, len(data.Hosts))
	// Nmap receives only one explicit target. Refuse unexpected multi-host XML.
	if len(data.Hosts) > 1 {
		return nil, errors.New("unexpected multi-host Nmap XML response")
	}
	for _, x := range data.Hosts {
		host := NmapHost{Status: cleanNmapText(x.Status.State, 32), Reason: cleanNmapText(x.Status.Reason, 64), Ports: []NmapPort{}, ExtraPortStates: map[string]int{}}
		for _, addr := range x.Addresses {
			if addr.Type == "ipv4" || addr.Type == "ipv6" {
				if ip := net.ParseIP(addr.Address); ip != nil {
					host.Addresses = append(host.Addresses, ip.String())
				}
			}
		}
		for _, hn := range x.Hostnames {
			if n := cleanNmapText(hn.Name, 253); n != "" && len(host.Hostnames) < 16 {
				host.Hostnames = append(host.Hostnames, n)
			}
		}
		if secs, err := strconv.ParseInt(x.Uptime.Seconds, 10, 64); err == nil && secs >= 0 {
			host.UptimeSeconds = secs
		}
		for _, osmatch := range x.OS.Matches {
			if len(host.OSMatches) >= 10 {
				break
			}
			accuracy, _ := strconv.Atoi(osmatch.Accuracy)
			if accuracy >= 0 && accuracy <= 100 {
				host.OSMatches = append(host.OSMatches, NmapOSMatch{Name: cleanNmapText(osmatch.Name, 200), Accuracy: accuracy})
			}
		}
		for _, extra := range x.Ports.Extra {
			n, e := strconv.Atoi(extra.Count)
			state := cleanNmapText(extra.State, 32)
			if e == nil && n >= 0 && state != "" {
				host.ExtraPortStates[state] += n
			}
		}
		seen := map[string]bool{}
		for _, p := range x.Ports.Ports {
			number, err := strconv.Atoi(p.PortID)
			if err != nil || number < 1 || number > 65535 || (p.Protocol != "tcp" && p.Protocol != "udp") {
				continue
			}
			key := p.Protocol + ":" + strconv.Itoa(number)
			if seen[key] {
				continue
			}
			seen[key] = true
			np := NmapPort{Protocol: p.Protocol, Number: number, State: cleanNmapText(p.State.State, 32), Reason: cleanNmapText(p.State.Reason, 64),
				Service: cleanNmapText(p.Service.Name, 96), Product: cleanNmapText(p.Service.Product, 160), Version: cleanNmapText(p.Service.Version, 96),
				ExtraInfo: cleanNmapText(p.Service.ExtraInfo, 200), Tunnel: cleanNmapText(p.Service.Tunnel, 48), Method: cleanNmapText(p.Service.Method, 24)}
			if c, e := strconv.Atoi(p.Service.Confidence); e == nil && c >= 0 && c <= 10 {
				np.Confidence = c
			}
			for _, cpe := range p.Service.CPE {
				if len(np.CPE) >= 8 {
					break
				}
				np.CPE = append(np.CPE, cleanNmapText(cpe, 240))
			}
			for _, sc := range p.Scripts {
				if len(np.Scripts) >= 32 {
					break
				}
				np.Scripts = append(np.Scripts, NmapScript{ID: cleanNmapText(sc.ID, 80), Output: cleanNmapText(sc.Output, 3000)})
			}
			host.Ports = append(host.Ports, np)
		}
		sort.Slice(host.Ports, func(i, j int) bool {
			if host.Ports[i].Protocol != host.Ports[j].Protocol {
				return host.Ports[i].Protocol < host.Ports[j].Protocol
			}
			return host.Ports[i].Number < host.Ports[j].Number
		})
		hosts = append(hosts, host)
	}
	return hosts, nil
}

func portFindings(hosts []NmapHost, target string) ([]Finding, int, int) {
	items := []Finding{}
	tcp, udp := 0, 0
	for _, host := range hosts {
		for _, p := range host.Ports {
			if p.State != "open" {
				continue
			}
			if p.Protocol == "tcp" {
				tcp++
			} else {
				udp++
			}
			if len(items) >= 1000 {
				continue
			}
			service := p.Service
			if service == "" {
				service = "unknown"
			}
			details := service
			if p.Product != "" {
				details += " / " + p.Product
			}
			if p.Version != "" {
				details += " " + p.Version
			}
			if p.ExtraInfo != "" {
				details += " / " + p.ExtraInfo
			}
			loc := net.JoinHostPort(target, strconv.Itoa(p.Number)) + "/" + p.Protocol
			items = append(items, newFinding("info", "network-discovery", fmt.Sprintf("Open %s port %d (%s)", strings.ToUpper(p.Protocol), p.Number, service),
				"Nmap reported an open port. An open port, banner or CPE is not proof of a vulnerability.",
				"Observed service: "+details, loc, 0, "Verify business necessity and restrict exposure to approved networks."))
		}
	}
	return items, tcp, udp
}

// LocateNmap honors a user override, the environment, then system discovery.
func LocateNmap(override string) (NmapStatus, error) {
	type candidate struct{ path, source string }
	candidates := []candidate{}
	if override != "" {
		candidates = append(candidates, candidate{override, "explicit override"})
	} else if env := os.Getenv("SECUBRAIN_NMAP_PATH"); env != "" {
		candidates = append(candidates, candidate{env, "environment"})
	} else {
		candidates = append(candidates, candidate{"nmap", "PATH"})
		if runtime.GOOS == "windows" {
			for _, root := range []string{os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)"), os.Getenv("LOCALAPPDATA")} {
				if root != "" {
					candidates = append(candidates, candidate{filepath.Join(root, "Nmap", "nmap.exe"), "standard installation"})
				}
			}
		}
	}
	for _, c := range candidates {
		if path, err := exec.LookPath(c.path); err == nil {
			return NmapStatus{Available: true, Binary: path, Source: c.source}, nil
		}
	}
	if override != "" {
		return NmapStatus{}, fmt.Errorf("Nmap not found at --nmap-bin path")
	}
	if os.Getenv("SECUBRAIN_NMAP_PATH") != "" {
		return NmapStatus{}, fmt.Errorf("Nmap not found at SECUBRAIN_NMAP_PATH")
	}
	return NmapStatus{}, errors.New("Nmap not installed or not found; install independently from https://nmap.org/download.html")
}
func DetectNmap(parent context.Context, override string) (NmapStatus, error) {
	status, err := LocateNmap(override)
	if err != nil {
		return status, err
	}
	ctx, cancel := context.WithTimeout(parent, 8*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, status.Binary, "--version").Output()
	if err != nil {
		return status, fmt.Errorf("cannot query Nmap version: %w", err)
	}
	status.Version = cleanNmapText(strings.SplitN(string(output), "\n", 2)[0], 160)
	if !strings.HasPrefix(status.Version, "Nmap version ") && !strings.HasPrefix(status.Version, "Nmap fixture ") {
		return status, errors.New("unexpected Nmap --version response")
	}
	return status, nil
}

func nmapTarget(cfg Config) string {
	if cfg.Target != "" {
		return cfg.Target
	}
	u, _ := url.Parse(cfg.URL)
	if u != nil {
		return u.Hostname()
	}
	return ""
}
func nmapProfile(cfg Config) string {
	if cfg.NmapProfile == "" {
		return "standard"
	}
	return cfg.NmapProfile
}
func nmapDuration(cfg Config) time.Duration {
	if cfg.NmapTimeout > 0 {
		return cfg.NmapTimeout
	}
	switch nmapProfile(cfg) {
	case "quick":
		return 100 * time.Second
	case "full":
		return 20 * time.Minute
	default:
		return 5 * time.Minute
	}
}
func nmapArgs(host string, cfg Config) []string {
	profile := nmapProfile(cfg)
	timeout := nmapDuration(cfg)
	args := []string{"-sT", "-sV", "-Pn", "-n", "--max-retries", "2", "--host-timeout", strconv.Itoa(int(timeout.Seconds())) + "s"}
	switch profile {
	case "quick":
		args = append(args, "-F", "--version-intensity", "2", "-T3", "--max-rate", "100")
	case "full":
		args = append(args, "-p-", "--version-intensity", "7", "-T3", "--max-rate", "250")
	default:
		args = append(args, "--version-intensity", "5", "-T3", "--max-rate", "150")
	}
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		args = append(args, "-6")
	}
	if cfg.NmapUDP {
		args = append(args, "-sU")
		if profile == "full" { // TCP 1-65535; UDP 1-1024 (explicit, may require privileges).
			for i, v := range args {
				if v == "-p-" {
					args = append(args[:i], append([]string{"-p", "T:1-65535,U:1-1024"}, args[i+1:]...)...)
					break
				}
			}
		}
	}
	if cfg.NmapOS {
		args = append(args, "-O", "--osscan-limit", "--max-os-tries", "1")
	}
	if cfg.NmapScripts {
		args = append(args, "--script", "default")
	}
	args = append(args, "-oX", "-", host)
	return args
}
func scanNmap(parent context.Context, cfg Config, r *Report) {
	host := nmapTarget(cfg)
	profile := nmapProfile(cfg)
	info := &NmapSummary{Status: "skipped", Target: host, Profile: profile, Mode: "TCP connect + service/version detection", Hosts: []NmapHost{}}
	if cfg.NmapUDP {
		info.Mode += " + UDP"
	}
	if cfg.NmapOS {
		info.Mode += " + OS fingerprint"
	}
	if cfg.NmapScripts {
		info.Mode += " + default NSE scripts"
	}
	r.Nmap = info
	status, err := DetectNmap(parent, cfg.NmapBinary)
	if err != nil {
		r.Warnings = append(r.Warnings, err.Error()+"; Nmap scan skipped")
		return
	}
	info.Version, info.BinarySource = status.Version, status.Source
	ctx, cancel := context.WithTimeout(parent, nmapDuration(cfg)+15*time.Second)
	defer cancel()
	start := time.Now()
	cmd := exec.CommandContext(ctx, status.Binary, nmapArgs(host, cfg)...)
	output := &cappedBuffer{max: nmapMaxXML}
	stderr := &cappedBuffer{max: 8192}
	cmd.Stdout = output
	cmd.Stderr = stderr
	err = cmd.Run()
	info.DurationMS = time.Since(start).Milliseconds()
	hosts, parseErr := parseNmapInventory(output.Bytes())
	if parseErr == nil {
		info.Hosts = hosts
		for _, h := range hosts {
			if h.Status == "up" {
				info.HostsUp++
			}
		}
		findings, tcp, udp := portFindings(hosts, host)
		info.OpenTCPPorts = tcp
		info.OpenUDPPorts = udp
		r.Findings = append(r.Findings, findings...)
		if tcp+udp > 1000 {
			r.Warnings = append(r.Warnings, "Port findings capped at 1000 entries; full network inventory retained in nmap.hosts")
		}
	}
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		info.Status = "failed"
		r.Warnings = append(r.Warnings, "Nmap timed out before completion; results may be partial")
	case err != nil:
		info.Status = "failed"
		if parseErr == nil {
			info.Status = "partial"
		}
		msg := "Nmap exited with error; check local permissions, Npcap installation, and target reachability"
		if ctx.Err() == context.Canceled {
			msg = "Nmap cancelled by caller"
		}
		r.Warnings = append(r.Warnings, msg)
	case parseErr != nil:
		info.Status = "failed"
		r.Warnings = append(r.Warnings, "Nmap output could not be parsed: "+parseErr.Error())
	default:
		info.Status = "completed"
	}
}
