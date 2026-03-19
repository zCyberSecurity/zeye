package probe

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"time"
	"unicode"
)

// TCPProber grabs raw TCP banners from services.
type TCPProber struct {
	timeout time.Duration
}

func NewTCPProber(timeout time.Duration) *TCPProber {
	return &TCPProber{timeout: timeout}
}

func (t *TCPProber) Protocol() string { return "tcp" }

func (t *TCPProber) ShouldProbe(port uint16) bool {
	// HTTP prober handles web ports; skip them here to avoid double-probing
	// when HTTP probe already succeeded.
	return true
}

func (t *TCPProber) Probe(ctx context.Context, ip string, port uint16) (*ProbeResult, error) {
	addr := fmt.Sprintf("%s:%d", ip, port)
	d := &net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	deadline, ok := ctx.Deadline()
	if ok {
		conn.SetDeadline(deadline)
	} else {
		conn.SetDeadline(time.Now().Add(t.timeout))
	}

	// Read banner (wait for server to send something)
	reader := bufio.NewReader(conn)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	banner, _ := reader.ReadString('\n')

	if banner == "" {
		// Try sending a newline to elicit a response
		conn.Write([]byte("\r\n"))
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		banner, _ = reader.ReadString('\n')
	}

	banner = sanitizeBanner(banner)
	appProto := guessProtocol(port, banner)

	return &ProbeResult{
		IP:        ip,
		Port:      port,
		AppProto:  appProto,
		Banner:    banner,
		Timestamp: time.Now(),
	}, nil
}

func sanitizeBanner(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) || r == '\t' {
			return r
		}
		return -1
	}, s)
	s = strings.TrimSpace(s)
	if len(s) > 512 {
		s = s[:512]
	}
	return s
}

func guessProtocol(port uint16, banner string) string {
	b := strings.ToLower(banner)
	switch {
	case strings.HasPrefix(b, "ssh"):
		return "ssh"
	case strings.HasPrefix(b, "220") && strings.Contains(b, "ftp"):
		return "ftp"
	case strings.HasPrefix(b, "220") && strings.Contains(b, "smtp"):
		return "smtp"
	case strings.HasPrefix(b, "+ok"):
		return "pop3"
	case strings.HasPrefix(b, "* ok"):
		return "imap"
	case strings.HasPrefix(b, "http/"):
		return "http"
	case port == 3306 || strings.Contains(b, "mysql"):
		return "mysql"
	case port == 5432 || strings.Contains(b, "postgresql"):
		return "postgresql"
	case port == 6379 || strings.Contains(b, "redis"):
		return "redis"
	case port == 27017:
		return "mongodb"
	case port == 5900:
		return "vnc"
	case port == 3389:
		return "rdp"
	default:
		return "tcp"
	}
}
