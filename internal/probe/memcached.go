package probe

import (
	"bufio"
	"context"
	"fmt"
	"strings"
	"time"
)

// MemcachedProber identifies Memcached services.
// Sends the "version" command and parses the VERSION response.
type MemcachedProber struct{ timeout time.Duration }

func NewMemcachedProber(timeout time.Duration) *MemcachedProber { return &MemcachedProber{timeout} }
func (p *MemcachedProber) Protocol() string                     { return "memcached" }
func (p *MemcachedProber) ShouldProbe(port uint16) bool         { return port == 11211 }

func (p *MemcachedProber) Probe(ctx context.Context, ip string, port uint16) (*ProbeResult, error) {
	conn, err := dialTCP(ctx, ip, port)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(p.timeout))

	if _, err := conn.Write([]byte("version\r\n")); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}

	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(strings.ToUpper(line), "VERSION") {
		return nil, fmt.Errorf("not memcached: %q", line)
	}
	return &ProbeResult{IP: ip, Port: port, AppProto: "memcached", Banner: line, Timestamp: time.Now()}, nil
}
