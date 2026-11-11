package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const Version = "0.3.0"

type Config struct {
	Path        string
	URL         string
	Output      string
	Authorized  bool
	Nmap        bool
	NmapBinary  string
	Target      string
	NmapProfile string
	NmapTimeout time.Duration
	NmapUDP     bool
	NmapOS      bool
	NmapScripts bool
	MaxFiles    int
	Timeout     time.Duration
}

type Finding struct {
	ID             string `json:"id"`
	Severity       string `json:"severity"`
	Category       string `json:"category"`
	Title          string `json:"title"`
	Description    string `json:"description"`
	Evidence       string `json:"evidence"`
	Location       string `json:"location,omitempty"`
	Line           int    `json:"line,omitempty"`
	Recommendation string `json:"recommendation"`
}

type Stats struct {
	FilesInspected int   `json:"files_inspected"`
	BytesInspected int64 `json:"bytes_inspected"`
	High           int   `json:"high"`
	Medium         int   `json:"medium"`
	Low            int   `json:"low"`
	Info           int   `json:"info"`
}

type Report struct {
	Tool       string       `json:"tool"`
	Version    string       `json:"version"`
	StartedAt  time.Time    `json:"started_at"`
	FinishedAt time.Time    `json:"finished_at"`
	Path       string       `json:"path,omitempty"`
	URL        string       `json:"url,omitempty"`
	Target     string       `json:"target,omitempty"`
	Stats      Stats        `json:"stats"`
	Findings   []Finding    `json:"findings"`
	Warnings   []string     `json:"warnings"`
	Checks     []string     `json:"checks"`
	Nmap       *NmapSummary `json:"nmap,omitempty"`
}

func (c *Config) validate() error {
	if c.Path == "" && c.URL == "" && c.Target == "" {
		return errors.New("provide a project path, web URL, or an Nmap --target")
	}
	if c.NmapBinary != "" && !c.Nmap {
		return errors.New("--nmap-bin requires --nmap")
	}
	if c.Nmap && c.URL == "" && c.Target == "" {
		return errors.New("--nmap requires --target or --url")
	}
	if c.Target != "" && !c.Nmap {
		return errors.New("--target requires --nmap")
	}
	if (c.Nmap || c.Target != "") && !c.Authorized {
		return errors.New("Nmap requires --authorized and explicit permission from the target owner")
	}
	if !c.Nmap && (c.NmapProfile != "" || c.NmapTimeout != 0 || c.NmapUDP || c.NmapOS || c.NmapScripts) {
		return errors.New("Nmap options require --nmap")
	}
	if c.Nmap {
		if c.NmapProfile == "" {
			c.NmapProfile = "standard"
		}
		if c.NmapProfile != "quick" && c.NmapProfile != "standard" && c.NmapProfile != "full" {
			return errors.New("--nmap-profile must be quick, standard or full")
		}
		if c.NmapTimeout != 0 && (c.NmapTimeout < 15*time.Second || c.NmapTimeout > 30*time.Minute) {
			return errors.New("--nmap-timeout must be between 15s and 30m")
		}
	}
	if c.Target != "" {
		if err := validateNmapTarget(c.Target); err != nil {
			return err
		}
	}
	if c.URL != "" {
		if !c.Authorized {
			return errors.New("web checks require --authorized (only assess systems you own or are authorized to test)")
		}
		u, err := url.Parse(c.URL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.User != nil {
			return errors.New("--url must be a valid http(s) URL without embedded credentials")
		}
		if strings.ContainsAny(u.Hostname(), " \t\n") || strings.HasPrefix(u.Hostname(), "-") {
			return errors.New("invalid URL hostname")
		}
		if c.Target != "" && !strings.EqualFold(c.Target, u.Hostname()) {
			return errors.New("--target must match the hostname in --url; cross-target scans are not supported")
		}
		if c.Nmap {
			if err := validateNmapTarget(u.Hostname()); err != nil {
				return fmt.Errorf("invalid Nmap URL hostname: %w", err)
			}
		}
		if u.Fragment != "" || u.RawQuery != "" {
			return errors.New("URL query parameters and fragments are not supported; provide a clean endpoint URL")
		}
	}
	if c.Path != "" {
		abs, err := filepath.Abs(c.Path)
		if err != nil {
			return fmt.Errorf("resolve path: %w", err)
		}
		stat, err := os.Stat(abs)
		if err != nil {
			return fmt.Errorf("read project path: %w", err)
		}
		if !stat.IsDir() {
			return errors.New("project path must be a directory")
		}
		c.Path = abs
	}
	if c.Output == "" {
		c.Output = "secubrain-reports"
	}
	abs, err := filepath.Abs(c.Output)
	if err != nil {
		return fmt.Errorf("resolve output directory: %w", err)
	}
	c.Output = abs
	if c.MaxFiles <= 0 {
		c.MaxFiles = 5000
	}
	if c.MaxFiles > 50000 {
		return errors.New("--max-files must be <= 50000")
	}
	if c.Timeout <= 0 {
		c.Timeout = 8 * time.Second
	}
	if c.Timeout > 60*time.Second {
		return errors.New("--timeout must be <= 60 seconds")
	}
	return nil
}

func validateNmapTarget(target string) error {
	if len(target) == 0 || len(target) > 253 || strings.HasPrefix(target, "-") || (strings.ContainsAny(target, " \t\n\r/\\[]:%@") && net.ParseIP(target) == nil) {
		return errors.New("--target must be one IP address or DNS hostname, not a URL, CIDR or flag")
	}
	if net.ParseIP(target) != nil {
		return nil
	}
	if strings.HasSuffix(target, ".") {
		target = strings.TrimSuffix(target, ".")
	}
	if target == "" {
		return errors.New("--target cannot be empty")
	}
	for _, label := range strings.Split(target, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("invalid DNS hostname in --target")
		}
		for _, c := range label {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
				return errors.New("invalid DNS hostname in --target")
			}
		}
	}
	return nil
}

func newFinding(severity, category, title, detail, evidence, location string, line int, recommendation string) Finding {
	hash := sha256.Sum256([]byte(category + "|" + title + "|" + location + "|" + fmt.Sprint(line)))
	return Finding{ID: "SB-" + strings.ToUpper(hex.EncodeToString(hash[:4])), Severity: severity, Category: category, Title: title,
		Description: detail, Evidence: evidence, Location: location, Line: line, Recommendation: recommendation}
}

func summarize(r *Report) {
	sort.SliceStable(r.Findings, func(i, j int) bool {
		levels := map[string]int{"high": 0, "medium": 1, "low": 2, "info": 3}
		a, b := levels[r.Findings[i].Severity], levels[r.Findings[j].Severity]
		if a != b {
			return a < b
		}
		if r.Findings[i].Location != r.Findings[j].Location {
			return r.Findings[i].Location < r.Findings[j].Location
		}
		if r.Findings[i].Line != r.Findings[j].Line {
			return r.Findings[i].Line < r.Findings[j].Line
		}
		return r.Findings[i].Title < r.Findings[j].Title
	})
	for _, f := range r.Findings {
		switch f.Severity {
		case "high":
			r.Stats.High++
		case "medium":
			r.Stats.Medium++
		case "low":
			r.Stats.Low++
		default:
			r.Stats.Info++
		}
	}
}

// Run executes a bounded, deterministic audit. It does not exploit vulnerabilities.
func Run(ctx context.Context, cfg Config, progress func(string)) (Report, error) {
	report := Report{Tool: "SecuBrain", Version: Version, StartedAt: time.Now().UTC(), Findings: []Finding{}, Warnings: []string{}, Checks: []string{}}
	if err := cfg.validate(); err != nil {
		return report, err
	}
	report.Path, report.URL, report.Target = cfg.Path, cfg.URL, cfg.Target
	say := func(s string) {
		if progress != nil {
			progress(s)
		}
	}
	if cfg.Path != "" {
		say("Inspecting project files...")
		if err := scanFiles(ctx, cfg, &report); err != nil {
			return report, err
		}
		report.Checks = append(report.Checks, "Local file patterns, credential exposure indicators, .gitignore checks")
	}
	if cfg.URL != "" {
		say("Checking HTTP response headers (no crawling)...")
		scanWeb(ctx, cfg, &report)
		report.Checks = append(report.Checks, "HTTP response headers (HEAD request only, no redirects)")
	}
	if cfg.Nmap {
		say("Running Nmap " + cfg.NmapProfile + " network inventory...")
		scanNmap(ctx, cfg, &report)
		report.Checks = append(report.Checks, "Optional Nmap TCP connect and light service discovery (100 common ports, low rate, 80s host limit)")
	}
	summarize(&report)
	report.FinishedAt = time.Now().UTC()
	say("Writing HTML, Markdown and JSON reports...")
	if err := WriteReports(cfg.Output, report); err != nil {
		return report, err
	}
	if cfg.Nmap && report.Nmap != nil && report.Nmap.Status != "completed" {
		return report, fmt.Errorf("Nmap scan %s; review report warnings and installation", report.Nmap.Status)
	}
	return report, nil
}
