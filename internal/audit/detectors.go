package audit

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const maxSingleFile = 1 << 20 // 1 MiB
const maxTotalBytes = 30 << 20
const maxFindings = 250

var skippedDirs = map[string]bool{
	".git": true, "node_modules": true, ".next": true, "vendor": true, "dist": true, "build": true, "target": true,
	"__pycache__": true, ".venv": true, "venv": true, "coverage": true, ".cache": true, ".idea": true,
}
var allowedExts = map[string]bool{
	".go": true, ".py": true, ".js": true, ".ts": true, ".jsx": true, ".tsx": true, ".json": true,
	".yaml": true, ".yml": true, ".toml": true, ".env": true, ".xml": true, ".ini": true,
	".cfg": true, ".conf": true, ".config": true, ".php": true, ".rb": true, ".java": true,
	".cs": true, ".sh": true, ".sql": true, ".properties": true, ".txt": true, ".pem": true, ".key": true,
}
var (
	awsKeyRe      = regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)
	githubTokenRe = regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{25,}\b`)
	privateKeyRe  = regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----`)
	credentialRe  = regexp.MustCompile(`(?i)^\s*["']?(?:password|passwd|api[_-]?key|client[_-]?secret|auth[_-]?token|access[_-]?token|secret)["']?\s*[:=]\s*["']?([^"'#\s,;]{8,})`)
)

func scannable(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	if base == "dockerfile" || base == "makefile" || base == ".gitignore" || base == ".npmrc" || base == ".pypirc" || base == "go.mod" {
		return true
	}
	if base == ".env" || strings.HasPrefix(base, ".env.") {
		return true
	}
	return allowedExts[strings.ToLower(filepath.Ext(base))]
}

func scanFiles(ctx context.Context, cfg Config, r *Report) error {
	// If outputs live in the project directory, exclude them from the scan.
	excludeOut := cfg.Output
	exhausted := false
	err := filepath.WalkDir(cfg.Path, func(path string, d fs.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if walkErr != nil {
			r.Warnings = append(r.Warnings, fmt.Sprintf("Cannot inspect %s: %v", displayPath(cfg.Path, path), walkErr))
			return nil
		}
		if path == excludeOut || strings.HasPrefix(path, excludeOut+string(os.PathSeparator)) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if path != cfg.Path && skippedDirs[strings.ToLower(d.Name())] {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 || !d.Type().IsRegular() || !scannable(path) {
			return nil
		}
		if r.Stats.FilesInspected >= cfg.MaxFiles || r.Stats.BytesInspected >= maxTotalBytes || len(r.Findings) >= maxFindings {
			exhausted = true
			return filepath.SkipAll
		}
		info, err := d.Info()
		if err != nil || info.Size() > maxSingleFile {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			r.Warnings = append(r.Warnings, "Cannot read "+displayPath(cfg.Path, path))
			return nil
		}
		if bytes.IndexByte(raw, 0) >= 0 {
			return nil
		}
		r.Stats.FilesInspected++
		r.Stats.BytesInspected += int64(len(raw))
		rel := displayPath(cfg.Path, path)
		detectFile(rel, raw, r)
		return nil
	})
	if exhausted {
		r.Warnings = append(r.Warnings, "File, size or finding limit reached; results may be incomplete")
	}
	if err != nil {
		return err
	}
	checkEnvIgnore(cfg.Path, r)
	return nil
}

func displayPath(root, path string) string {
	p, err := filepath.Rel(root, path)
	if err != nil {
		return filepath.Base(path)
	}
	return filepath.ToSlash(p)
}

func detectFile(relativePath string, raw []byte, r *Report) {
	reader := bufio.NewReader(bytes.NewReader(raw))
	for lineNo := 1; ; lineNo++ {
		if len(r.Findings) >= maxFindings {
			return
		}
		line, err := reader.ReadString('\n')
		if line != "" {
			detectLine(relativePath, lineNo, line, r)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
	}
}

func detectLine(path string, lineNo int, line string, r *Report) {
	// Evidence intentionally never contains secret values or raw source lines.
	if privateKeyRe.MatchString(line) {
		r.Findings = append(r.Findings, newFinding("high", "credentials", "Private key material detected",
			"A private-key PEM header was found in a project file.", "Private-key header detected; key material redacted", path, lineNo,
			"Remove private keys from shared source, restrict file permissions, and rotate any exposed key."))
	}
	if githubTokenRe.MatchString(line) {
		r.Findings = append(r.Findings, newFinding("high", "credentials", "Potential GitHub token in source",
			"A token-like credential was detected. This is a pattern match, not a validity check.", "Token-like value detected; value redacted", path, lineNo,
			"Revoke/rotate if genuine; use a secrets manager or environment-based configuration."))
	}
	if awsKeyRe.MatchString(line) {
		r.Findings = append(r.Findings, newFinding("medium", "credentials", "Potential cloud access key identifier",
			"A cloud access-key ID pattern was found. An ID alone does not prove account compromise.", "Cloud key identifier pattern; value redacted", path, lineNo,
			"Verify whether the identifier is real, rotate if exposed, and avoid committing credentials."))
	}
	m := credentialRe.FindStringSubmatch(line)
	if len(m) > 1 && !looksLikePlaceholder(m[1]) {
		r.Findings = append(r.Findings, newFinding("medium", "credentials", "Potential hardcoded credential",
			"An assignment to a credential-like key appears to contain a literal value.", "Credential-style assignment detected; value redacted", path, lineNo,
			"Verify whether it is a secret; move genuine secrets out of source and rotate if necessary."))
	}
}

func looksLikePlaceholder(v string) bool {
	x := strings.ToLower(strings.Trim(v, "\"'`"))
	if strings.HasPrefix(x, "${") || strings.HasPrefix(x, "$(") || strings.HasPrefix(x, "$env") || strings.HasPrefix(x, "process.env") || strings.HasPrefix(x, "os.getenv") {
		return true
	}
	for _, s := range []string{"example", "sample", "placeholder", "changeme", "replace_me", "your_", "dummy", "mock", "testvalue", "undefined", "null", "<", "none"} {
		if strings.Contains(x, s) {
			return true
		}
	}
	return false
}

func checkEnvIgnore(root string, r *Report) {
	_, err := os.Stat(filepath.Join(root, ".env"))
	if err != nil {
		return
	}
	raw, err := os.ReadFile(filepath.Join(root, ".gitignore"))
	ignored := false
	if err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			x := strings.TrimSpace(line)
			if x == ".env" || x == "/.env" || x == ".env*" || x == ".env.*" || x == "*.env" {
				ignored = true
				break
			}
		}
	}
	if !ignored {
		r.Findings = append(r.Findings, newFinding("medium", "repository", ".env file may not be Git-ignored",
			"A root .env file exists, but no matching common .gitignore rule was found. This does not prove it is committed.", "Root .env exists; common ignore rule absent", ".env", 0,
			"Add an appropriate .gitignore pattern, check Git tracking status, and rotate secrets if already published."))
	}
}
