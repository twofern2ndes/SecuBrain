package audit

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/url"
	"os/exec"
	"strings"
	"time"
)

type nmapXML struct {
	Hosts []struct {
		Ports struct {
			Ports []struct {
				Protocol string `xml:"protocol,attr"`
				PortID   string `xml:"portid,attr"`
				State    struct {
					State string `xml:"state,attr"`
				} `xml:"state"`
				Service struct {
					Name string `xml:"name,attr"`
				} `xml:"service"`
			} `xml:"port"`
		} `xml:"ports"`
	} `xml:"host"`
}

func parseNmapOutput(raw []byte, host string) []Finding {
	var data nmapXML
	if xml.Unmarshal(raw, &data) != nil {
		return nil
	}
	findings := []Finding{}
	for _, h := range data.Hosts {
		for _, p := range h.Ports.Ports {
			if p.State.State != "open" || p.Protocol != "tcp" {
				continue
			}
			service := p.Service.Name
			if service == "" {
				service = "unknown service"
			}
			findings = append(findings, newFinding("info", "network-discovery", fmt.Sprintf("Open TCP port %s (%s)", p.PortID, service),
				"A TCP port responded as open during limited discovery. An open port is not itself a vulnerability.",
				"Nmap TCP connect scan (100 common ports)", host+":"+p.PortID, 0,
				"Verify the service is expected and protected by appropriate network access controls."))
		}
	}
	return findings
}

func scanNmap(parent context.Context, cfg Config, r *Report) {
	binary, err := exec.LookPath("nmap")
	if err != nil {
		r.Warnings = append(r.Warnings, "Nmap is not installed or is unavailable on PATH; optional port check skipped")
		return
	}
	u, _ := url.Parse(cfg.URL)
	host := u.Hostname()
	// Strictly bound to the single, explicitly authorized hostname. No shell invocation.
	ctx, cancel := context.WithTimeout(parent, 40*time.Second)
	defer cancel()
	args := []string{"-sT", "-Pn", "-F", "-T2", "--max-retries", "1", "--host-timeout", "30s", "-oX", "-", host}
	cmd := exec.CommandContext(ctx, binary, args...)
	data, err := cmd.Output()
	if err != nil {
		r.Warnings = append(r.Warnings, "Nmap did not complete; network findings omitted: "+strings.TrimSpace(err.Error()))
		return
	}
	items := parseNmapOutput(data, host)
	if items == nil {
		r.Warnings = append(r.Warnings, "Unable to parse Nmap XML output")
		return
	}
	r.Findings = append(r.Findings, items...)
}
