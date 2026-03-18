package probe

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// ── SMTP ──────────────────────────────────────────────────────────────────────

type SMTPProber struct{ timeout time.Duration }

func NewSMTPProber(timeout time.Duration) *SMTPProber { return &SMTPProber{timeout} }
func (p *SMTPProber) Protocol() string                { return "smtp" }
func (p *SMTPProber) ShouldProbe(port uint16) bool {
	return port == 25 || port == 465 || port == 587
}

func (p *SMTPProber) Probe(ctx context.Context, ip string, port uint16) (*ProbeResult, error) {
	conn, err := mailDial(ctx, ip, port)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(p.timeout))

	banner, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	banner = sanitizeBanner(banner)
	if !strings.HasPrefix(banner, "220") {
		return nil, fmt.Errorf("not smtp")
	}
	proto := "smtp"
	if port == 465 {
		proto = "smtps"
	}
	r := &ProbeResult{IP: ip, Port: port, AppProto: proto, Banner: banner, Timestamp: time.Now()}
	r.TLSSubject, r.TLSIssuer, r.TLSAltNames, r.TLSExpiry = tlsCertInfo(conn)
	return r, nil
}

// ── IMAP ──────────────────────────────────────────────────────────────────────

type IMAPProber struct{ timeout time.Duration }

func NewIMAPProber(timeout time.Duration) *IMAPProber { return &IMAPProber{timeout} }
func (p *IMAPProber) Protocol() string                { return "imap" }
func (p *IMAPProber) ShouldProbe(port uint16) bool    { return port == 143 || port == 993 }

func (p *IMAPProber) Probe(ctx context.Context, ip string, port uint16) (*ProbeResult, error) {
	conn, err := mailDial(ctx, ip, port)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(p.timeout))

	banner, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	banner = sanitizeBanner(banner)
	if !strings.HasPrefix(strings.ToUpper(banner), "* OK") {
		return nil, fmt.Errorf("not imap")
	}
	proto := "imap"
	if port == 993 {
		proto = "imaps"
	}
	r := &ProbeResult{IP: ip, Port: port, AppProto: proto, Banner: banner, Timestamp: time.Now()}
	r.TLSSubject, r.TLSIssuer, r.TLSAltNames, r.TLSExpiry = tlsCertInfo(conn)
	return r, nil
}

// ── POP3 ──────────────────────────────────────────────────────────────────────

type POP3Prober struct{ timeout time.Duration }

func NewPOP3Prober(timeout time.Duration) *POP3Prober { return &POP3Prober{timeout} }
func (p *POP3Prober) Protocol() string                { return "pop3" }
func (p *POP3Prober) ShouldProbe(port uint16) bool    { return port == 110 || port == 995 }

func (p *POP3Prober) Probe(ctx context.Context, ip string, port uint16) (*ProbeResult, error) {
	conn, err := mailDial(ctx, ip, port)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(p.timeout))

	banner, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	banner = sanitizeBanner(banner)
	if !strings.HasPrefix(strings.ToUpper(banner), "+OK") {
		return nil, fmt.Errorf("not pop3")
	}
	proto := "pop3"
	if port == 995 {
		proto = "pop3s"
	}
	r := &ProbeResult{IP: ip, Port: port, AppProto: proto, Banner: banner, Timestamp: time.Now()}
	r.TLSSubject, r.TLSIssuer, r.TLSAltNames, r.TLSExpiry = tlsCertInfo(conn)
	return r, nil
}

// mailDial dials TLS for known TLS-first ports, plain TCP otherwise.
func mailDial(ctx context.Context, ip string, port uint16) (net.Conn, error) {
	if port == 465 || port == 993 || port == 995 {
		return dialTLS(ctx, ip, port)
	}
	return dialTCP(ctx, ip, port)
}
