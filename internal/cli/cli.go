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
)

func Run(args []string) int {
	if len(args) == 0 {
		return repl()
	}
	switch args[0] {
	case "scan":
		return scan(args[1:])
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
	fmt.Printf(`SECUBRAIN v%s — deterministic security auditor (no AI)

Usage:
  secubrain                         Start interactive terminal
  secubrain scan --path ./project   Audit local source and configuration
  secubrain scan --path . --out ./reports
  secubrain scan --url https://example.org --authorized
  secubrain scan --url https://example.org --authorized --nmap
  secubrain version

Options for scan:
  --path        Project directory (optional with --url)
  --url         Explicitly authorized http(s) endpoint
  --authorized  Assert permission for web/network checks (required with --url)
  --nmap        Optional limited common-port discovery (requires installed Nmap)
  --out         Report directory (default: ./secubrain-reports)
  --max-files   File count limit (default: 5000)
  --timeout     Web request timeout (default: 8s)

Reports: report.html, report.md, report.json
No brute-force, exploitation, web crawling, or AI actions.
`, audit.Version)
}

func scan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var cfg audit.Config
	fs.StringVar(&cfg.Path, "path", "", "local project folder")
	fs.StringVar(&cfg.URL, "url", "", "authorized web URL")
	fs.StringVar(&cfg.Output, "out", "secubrain-reports", "output directory")
	fs.BoolVar(&cfg.Authorized, "authorized", false, "assert authorization for network checks")
	fs.BoolVar(&cfg.Nmap, "nmap", false, "enable optional Nmap common-port discovery")
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
	report, err := audit.Run(context.Background(), cfg, func(s string) { fmt.Println("[>]", s) })
	if err != nil {
		fmt.Fprintln(os.Stderr, "[ERROR]", err)
		return 1
	}
	output, _ := filepath.Abs(cfg.Output)
	fmt.Printf("\n[OK] Inspected %d files. Findings: %d high / %d medium / %d low / %d info\n", report.Stats.FilesInspected, report.Stats.High, report.Stats.Medium, report.Stats.Low, report.Stats.Info)
	if len(report.Warnings) > 0 {
		for _, w := range report.Warnings {
			fmt.Println("[!]", w)
		}
	}
	fmt.Println("[OK] Report:", filepath.Join(output, "report.html"))
	fmt.Println("[OK] JSON:  ", filepath.Join(output, "report.json"))
	fmt.Println("[OK] Markdown:", filepath.Join(output, "report.md"))
	return 0
}

// Accepts a single path before or after flags, including: scan ./project --out ./report.
func movePositionals(args []string) []string {
	var flags, positions []string
	takesValue := map[string]bool{"--path": true, "--url": true, "--out": true, "--max-files": true, "--timeout": true}
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
	fmt.Printf("SECUBRAIN / v%s\nDeterministic audits · No AI · Authorized targets only\nType 'help' for commands.\n\n", audit.Version)
	scanner := bufio.NewScanner(os.Stdin)
	lastReport := ""
	for {
		fmt.Print("secubrain > ")
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
		case "status":
			if lastReport == "" {
				fmt.Println("No scan launched in this session.")
			} else {
				fmt.Println("Last report:", lastReport)
			}
		case "scan":
			if scan(parts[1:]) == 0 {
				out := outputFromArgs(parts[1:])
				lastReport = filepath.Join(out, "report.html")
			}
		default:
			fmt.Println("Unknown command. Use: scan, status, help, version, exit")
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
