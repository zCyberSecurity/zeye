package probe

import (
	"context"
	"fmt"
	"time"
)

// SOCKS5Prober identifies SOCKS5 proxies.
// Sends a SOCKS5 greeting (no-auth) and expects a valid server choice response.
type SOCKS5Prober struct{ timeout time.Duration }

func NewSOCKS5Prober(timeout time.Duration) *SOCKS5Prober { return &SOCKS5Prober{timeout} }
func (p *SOCKS5Prober) Protocol() string                  { return "socks5" }
func (p *SOCKS5Prober) ShouldProbe(port uint16) bool {
	return port == 1080 || port == 1081 || port == 10080
}

func (p *SOCKS5Prober) Probe(ctx context.Context, ip string, port uint16) (*ProbeResult, error) {
	conn, err := dialTCP(ctx, ip, port)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(p.timeout))

	// Greeting: VER=5, NMETHODS=1, METHOD=0 (no auth)
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}

	resp := make([]byte, 2)
	if _, err := conn.Read(resp); err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	// VER must be 5; METHOD 0x00 = no auth, 0xFF = no acceptable method
	if resp[0] != 0x05 || resp[1] == 0xFF {
		return nil, fmt.Errorf("not socks5")
	}
	return &ProbeResult{IP: ip, Port: port, AppProto: "socks5", Banner: "SOCKS5", Timestamp: time.Now()}, nil
}
