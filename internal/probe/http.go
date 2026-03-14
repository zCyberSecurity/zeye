package probe

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// httpPorts are ports where HTTP is attempted first.
var httpPorts = map[uint16]bool{
	80: true, 8080: true, 8000: true, 8008: true, 8888: true,
	3000: true, 5000: true, 9090: true, 9000: true, 7070: true,
}

// httpsPorts are ports where HTTPS is attempted first.
var httpsPorts = map[uint16]bool{
	443: true, 8443: true, 4443: true, 10443: true,
}

// HTTPProber handles HTTP and HTTPS protocol detection.
type HTTPProber struct {
	timeout time.Duration
}

func NewHTTPProber(timeout time.Duration) *HTTPProber {
	return &HTTPProber{timeout: timeout}
}

func (h *HTTPProber) Protocol() string { return "http" }

func (h *HTTPProber) ShouldProbe(port uint16) bool {
	return httpPorts[port] || httpsPorts[port] || true // try HTTP on all ports
}

func (h *HTTPProber) Probe(ctx context.Context, ip string, port uint16) (*ProbeResult, error) {
	addr := fmt.Sprintf("%s:%d", ip, port)

	// Determine probe order based on port
	var schemes []string
	if httpsPorts[port] {
		schemes = []string{"https", "http"}
	} else if httpPorts[port] {
		schemes = []string{"http", "https"}
	} else {
		schemes = []string{"http", "https"}
	}

	var lastErr error
	for _, scheme := range schemes {
		target := fmt.Sprintf("%s://%s", scheme, addr)
		result, err := h.probeURL(ctx, target, ip, port)
		if err == nil {
			return result, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func (h *HTTPProber) probeURL(ctx context.Context, rawURL, ip string, port uint16) (*ProbeResult, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         ip,
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
		DialContext: (&net.Dialer{
			Timeout: h.timeout / 2,
		}).DialContext,
		TLSHandshakeTimeout:   h.timeout / 2,
		ResponseHeaderTimeout: h.timeout,
	}

	var redirectURL string
	client := &http.Client{
		Transport: transport,
		Timeout:   h.timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			redirectURL = req.URL.String()
			return nil
		},
	}

	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read body (limit to 256KB)
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))

	title := extractTitle(bodyBytes)
	headers := flattenHeaders(resp.Header)

	scheme := "http"
	if u, _ := url.Parse(rawURL); u != nil {
		scheme = u.Scheme
	}

	result := &ProbeResult{
		IP:          ip,
		Port:        port,
		AppProto:    scheme,
		StatusCode:  resp.StatusCode,
		Title:       title,
		Headers:     headers,
		Body:        string(bytes.ToValidUTF8(bodyBytes, []byte("?"))),
		Server:      resp.Header.Get("Server"),
		RedirectURL: redirectURL,
		Timestamp:   time.Now(),
	}

	// Extract TLS certificate info for HTTPS
	if scheme == "https" && resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		cert := resp.TLS.PeerCertificates[0]
		result.TLSSubject = cert.Subject.String()
		result.TLSIssuer = cert.Issuer.String()
		result.TLSExpiry = cert.NotAfter
		result.TLSAltNames = extractAltNames(cert)
	}

	return result, nil
}

func extractTitle(body []byte) string {
	m := titleRe.FindSubmatch(body)
	if m == nil {
		return ""
	}
	title := string(m[1])
	// Collapse whitespace
	title = strings.Join(strings.Fields(title), " ")
	if len(title) > 256 {
		title = title[:256]
	}
	return title
}

func flattenHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		out[strings.ToLower(k)] = strings.Join(v, "; ")
	}
	return out
}

func extractAltNames(cert *x509.Certificate) []string {
	var names []string
	names = append(names, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		names = append(names, ip.String())
	}
	return names
}
