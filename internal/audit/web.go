package audit

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

func scanWeb(ctx context.Context, cfg Config, r *Report) {
	u, _ := url.Parse(cfg.URL) // validated by Run
	client := &http.Client{Timeout: cfg.Timeout, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, u.String(), nil)
	if err != nil {
		r.Warnings = append(r.Warnings, "Unable to create HTTP header request")
		return
	}
	req.Header.Set("User-Agent", "SecuBrain/"+Version+" (authorized security header audit)")
	resp, err := client.Do(req)
	if err != nil {
		r.Warnings = append(r.Warnings, fmt.Sprintf("HTTP header request failed: %v", err))
		return
	}
	defer resp.Body.Close()
	loc := u.Scheme + "://" + u.Host + u.EscapedPath()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		r.Warnings = append(r.Warnings, fmt.Sprintf("HTTP status %d: redirect not followed to preserve target scope", resp.StatusCode))
	} else if resp.StatusCode == http.StatusMethodNotAllowed || resp.StatusCode == http.StatusNotImplemented {
		r.Warnings = append(r.Warnings, "Server does not support HEAD; no GET fallback was attempted")
		return
	} else if resp.StatusCode >= 400 {
		r.Warnings = append(r.Warnings, fmt.Sprintf("HTTP status %d; header analysis may not represent the application", resp.StatusCode))
	}
	add := func(severity, title, detail, recommend string) {
		r.Findings = append(r.Findings, newFinding(severity, "web-hardening", title, detail, "HTTP response header review", loc, 0, recommend))
	}
	host := strings.ToLower(u.Hostname())
	localDev := host == "localhost" || host == "127.0.0.1" || host == "::1"
	if u.Scheme == "http" && !localDev {
		add("medium", "Unencrypted HTTP endpoint", "The supplied endpoint uses plaintext HTTP.", "Use HTTPS with valid TLS configuration for production endpoints.")
	}
	if u.Scheme == "https" && resp.Header.Get("Strict-Transport-Security") == "" {
		add("low", "HSTS header not observed", "HSTS was absent from this response. Its suitability depends on deployment architecture.", "Consider an appropriate Strict-Transport-Security policy after validating HTTPS deployment.")
	}
	if strings.ToLower(resp.Header.Get("X-Content-Type-Options")) != "nosniff" {
		add("low", "X-Content-Type-Options not set to nosniff", "The response does not set X-Content-Type-Options: nosniff.", "Consider setting X-Content-Type-Options: nosniff.")
	}
	if resp.Header.Get("Content-Security-Policy") == "" {
		add("info", "Content-Security-Policy header not observed", "A CSP was not seen in this HEAD response; API and web requirements vary.", "Review whether a restrictive CSP is appropriate for browser-rendered content.")
	}
	if resp.Header.Get("X-Frame-Options") == "" && !strings.Contains(strings.ToLower(resp.Header.Get("Content-Security-Policy")), "frame-ancestors") {
		add("info", "Framing restriction not observed", "No X-Frame-Options or CSP frame-ancestors directive was observed.", "Consider frame-ancestors or X-Frame-Options for pages at risk of clickjacking.")
	}
}
