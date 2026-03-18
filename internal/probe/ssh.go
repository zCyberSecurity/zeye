package probe

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// SSHProber identifies SSH services and extracts the server version banner.
type SSHProber struct{ timeout time.Duration }

func NewSSHProber(timeout time.Duration) *SSHProber { return &SSHProber{timeout} }
func (p *SSHProber) Protocol() string               { return "ssh" }
func (p *SSHProber) ShouldProbe(port uint16) bool   { return port == 22 || port == 2222 }

func (p *SSHProber) Probe(ctx context.Context, ip string, port uint16) (*ProbeResult, error) {
	conn, err := dialTCP(ctx, ip, port)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(p.timeout))

	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return nil, fmt.Errorf("no banner")
	}
	banner := sanitizeBanner(string(buf[:n]))
	if !strings.HasPrefix(strings.ToUpper(banner), "SSH-") {
		return nil, fmt.Errorf("not ssh")
	}
	return &ProbeResult{
		IP: ip, Port: port, AppProto: "ssh", Banner: banner, Timestamp: time.Now(),
	}, nil
}
