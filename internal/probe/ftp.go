package probe

import (
	"bufio"
	"context"
	"fmt"
	"strings"
	"time"
)

// FTPProber identifies FTP services and extracts the server banner.
type FTPProber struct{ timeout time.Duration }

func NewFTPProber(timeout time.Duration) *FTPProber { return &FTPProber{timeout} }
func (p *FTPProber) Protocol() string               { return "ftp" }
func (p *FTPProber) ShouldProbe(port uint16) bool   { return port == 21 }

func (p *FTPProber) Probe(ctx context.Context, ip string, port uint16) (*ProbeResult, error) {
	conn, err := dialTCP(ctx, ip, port)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(p.timeout))

	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("read banner: %w", err)
	}
	banner := sanitizeBanner(line)
	if !strings.HasPrefix(banner, "220") {
		return nil, fmt.Errorf("not ftp: %q", banner)
	}
	return &ProbeResult{
		IP: ip, Port: port, AppProto: "ftp", Banner: banner, Timestamp: time.Now(),
	}, nil
}
