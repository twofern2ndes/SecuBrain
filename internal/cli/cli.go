package cli

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/twofern2ndes/SecuBrain/internal/audit"
	"github.com/twofern2ndes/SecuBrain/internal/ui"
)

func Run(args []string) int {
	if len(args) == 0 {
		return repl()
	}
	switch args[0] {
	case "scan":
		return scan(args[1:])
	case "nmap":
		return scan(append([]string{"--nmap"}, args[1:]...))
	case "doctor", "tools":
		return doctor(args[1:])
	case "help", "--help", "-h":
		usage()
		return 0
	case "version", "--version":
		fmt.Println("SecuBrain", audit.Version)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", args[0])
		usage()
		return 2
	}
}

func usage() {
	fmt.Printf(`SECUBRAIN v%s — deterministic security auditing (no AI)

Usage:
  secubrain                                      Interactive CLI
  secubrain doctor                               Locate installed Nmap
  secubrain scan --path ./project                Local code audit
  secubrain scan --url https://example.org --authorized
  secubrain nmap --target 192.0.2.10 --authorized
  secubrain nmap --target 192.0.2.10 --authorized --nmap-profile full
  secubrain scan --url https://example.org --authorized --nmap
  secubrain version

Network scan options (use with --nmap or with the 'nmap' command):
  --target           One explicitly authorized IP or DNS hostname
  --authorized       Mandatory confirmation of authorized network scope
  --nmap-profile     quick (100 TCP) | standard (1000 TCP) | full (65535 TCP)
  --nmap-udp         Also scan UDP (may require admin/root/Npcap)
  --nmap-os          Enable OS fingerprinting (requires raw packet privileges)
  --nmap-scripts     Enable Nmap's default NSE scripts (extra traffic)
  --nmap-timeout     Duration per scan (15s..30m, profile-dependent default)
  --nmap-bin         Path to a separately installed Nmap binary

General options:
  --path             Local directory (or single positional directory)
  --url              Authorized HTTP(S) endpoint, HEAD check only
  --out              Reports directory (default ./secubrain-reports)
  --max-files        Max local files (default 5000)
  --timeout          HTTP request timeout (default 8s)

Reports: report.json (full inventory), report.html, report.md.
The full Nmap profile scans all TCP ports, not all possible Nmap features.
Nmap/Npcap are third-party programs installed separately by the operator.
Use only systems you own or are explicitly authorized to assess.
`, audit.Version)
}

func doctor(args []string) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var nmapBinary string
	fs.StringVar(&nmapBinary, "nmap-bin", "", "path to installed Nmap")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return 2
	}
	term := ui.New(os.Stdout)
	term.Heading("SYSTEM / DEPENDENCY CHECK")
	term.KeyValue("SecuBrain", audit.Version+" · Go standard library")
	term.Success("No AI model or online service required for local audits")
	status, err := audit.DetectNmap(context.Background(), nmapBinary)
	if err != nil {
		term.Warn("Nmap: unavailable (optional)")
		term.KeyValue("Official download", "https://nmap.org/download.html")
		term.KeyValue("Note", "Install Nmap independently, then run doctor again")
	} else {
		term.Success("Nmap detected")
		term.KeyValue("Version", status.Version)
		term.KeyValue("Binary", status.Binary)
		term.KeyValue("Discovery", status.Source)
	}
	fmt.Println()
	return 0
}

func scan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var cfg audit.Config
	fs.StringVar(&cfg.Path, "path", "", "local project folder")
	fs.StringVar(&cfg.URL, "url", "", "authorized web URL")
	fs.StringVar(&cfg.Target, "target", "", "authorized single IP address or DNS hostname")
	fs.StringVar(&cfg.Output, "out", "secubrain-reports", "output directory")
	fs.BoolVar(&cfg.Authorized, "authorized", false, "assert authorization for network checks")
	fs.BoolVar(&cfg.Nmap, "nmap", false, "enable Nmap service discovery")
	fs.StringVar(&cfg.NmapProfile, "nmap-profile", "", "quick, standard, or full TCP profile")
	fs.BoolVar(&cfg.NmapUDP, "nmap-udp", false, "include UDP scanning")
	fs.BoolVar(&cfg.NmapOS, "nmap-os", false, "OS fingerprinting (admin/root required)")
	fs.BoolVar(&cfg.NmapScripts, "nmap-scripts", false, "run Nmap default NSE scripts")
	fs.DurationVar(&cfg.NmapTimeout, "nmap-timeout", 0, "Nmap execution timeout")
	fs.StringVar(&cfg.NmapBinary, "nmap-bin", "", "path to Nmap executable")
	fs.IntVar(&cfg.MaxFiles, "max-files", 5000, "maximum files to inspect")
	fs.DurationVar(&cfg.Timeout, "timeout", 8*time.Second, "network timeout")
	if err := fs.Parse(movePositionals(args)); err != nil {
		return 2
	}
	if fs.NArg() > 1 {
		fmt.Fprintln(os.Stderr, "Expected at most one positional path")
		return 2
	}
	if fs.NArg() == 1 {
		if cfg.Path != "" {
			fmt.Fprintln(os.Stderr, "Use either --path or a positional path, not both")
			return 2
		}
		cfg.Path = fs.Arg(0)
	}
	term := ui.New(os.Stdout)
	report, err := audit.Run(context.Background(), cfg, term.Step)
	if err != nil && report.FinishedAt.IsZero() {
		term.Error(err.Error())
		return 1
	}
	output, _ := filepath.Abs(cfg.Output)
	term.Heading("AUDIT / COMPLETE")
	term.KeyValue("Files", fmt.Sprint(report.Stats.FilesInspected))
	term.KeyValue("Indicators", fmt.Sprintf("%d high / %d medium / %d low / %d info", report.Stats.High, report.Stats.Medium, report.Stats.Low, report.Stats.Info))
	if report.Nmap != nil {
		term.KeyValue("Nmap", fmt.Sprintf("%s · %s · %d TCP / %d UDP ports open", report.Nmap.Status, report.Nmap.Profile, report.Nmap.OpenTCPPorts, report.Nmap.OpenUDPPorts))
		term.KeyValue("Hosts", fmt.Sprint(report.Nmap.HostsUp))
	}
	if len(report.Warnings) > 0 {
		for _, w := range report.Warnings {
			term.Warn(w)
		}
	}
	term.Success("Reports written")
	term.KeyValue("HTML", filepath.Join(output, "report.html"))
	term.KeyValue("JSON", filepath.Join(output, "report.json"))
	term.KeyValue("Markdown", filepath.Join(output, "report.md"))
	if err != nil {
		term.Error(err.Error())
		return 1
	}
	return 0
}

// Accepts a single path before or after flags, including: scan ./project --out ./report.
func movePositionals(args []string) []string {
	var flags, positions []string
	takesValue := map[string]bool{"--path": true, "--url": true, "--target": true, "--out": true, "--max-files": true, "--timeout": true, "--nmap-bin": true, "--nmap-profile": true, "--nmap-timeout": true}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			flags = append(flags, arg)
			if takesValue[arg] && i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
		} else {
			positions = append(positions, arg)
		}
	}
	return append(flags, positions...)
}

func repl() int {
	term := ui.New(os.Stdout)
	term.Banner(audit.Version)
	scanner := bufio.NewScanner(os.Stdin)
	lastReport := ""
	for {
		term.Prompt()
		if !scanner.Scan() {
			break
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts, err := splitCommand(line)
		if err != nil {
			fmt.Println("[ERROR]", err)
			continue
		}
		if len(parts) == 0 {
			continue
		}
		switch parts[0] {
		case "exit", "quit":
			return 0
		case "help":
			usage()
		case "version":
			fmt.Println("SecuBrain", audit.Version)
		case "doctor", "tools":
			doctor(parts[1:])
		case "status":
			if lastReport == "" {
				fmt.Println("No scan launched in this session.")
			} else {
				fmt.Println("Last report:", lastReport)
			}
		case "scan", "nmap":
			params := parts[1:]
			if parts[0] == "nmap" {
				params = append([]string{"--nmap"}, params...)
			}
			if scan(params) == 0 {
				out := outputFromArgs(params)
				lastReport = filepath.Join(out, "report.html")
			}
		default:
			term.Warn("Unknown command. Use: scan, nmap, doctor, status, help, version, exit")
		}
	}
	if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func outputFromArgs(args []string) string {
	out := "secubrain-reports"
	for i := 0; i < len(args); i++ {
		if args[i] == "--out" && i+1 < len(args) {
			out = args[i+1]
			i++
		} else if strings.HasPrefix(args[i], "--out=") {
			out = strings.TrimPrefix(args[i], "--out=")
		}
	}
	abs, _ := filepath.Abs(out)
	return abs
}

// Simple quoted command-line parsing for the interactive prompt, preserving Windows backslashes.
func splitCommand(s string) ([]string, error) {
	var args []string
	var current strings.Builder
	var quote rune
	haveToken := false
	for _, r := range s {
		if quote != 0 {
			if r == quote {
				quote = 0
			} else {
				current.WriteRune(r)
			}
			haveToken = true
			continue
		}
		if r == '"' || r == '\'' {
			quote = r
			haveToken = true
			continue
		}
		if r == ' ' || r == '\t' {
			if haveToken {
				args = append(args, current.String())
				current.Reset()
				haveToken = false
			}
			continue
		}
		current.WriteRune(r)
		haveToken = true
	}
	if quote != 0 {
		return nil, errors.New("unfinished quote in command")
	}
	if haveToken {
		args = append(args, current.String())
	}
	return args, nil
}
