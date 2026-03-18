package probe

import (
	"context"
	"fmt"
	"net"
	"time"
)

// NTPProber identifies NTP services via UDP.
type NTPProber struct{ timeout time.Duration }

func NewNTPProber(timeout time.Duration) *NTPProber { return &NTPProber{timeout} }
func (p *NTPProber) Protocol() string               { return "ntp" }
func (p *NTPProber) ShouldProbe(port uint16) bool   { return port == 123 }

// ntpRequest is a minimal NTP client request packet (48 bytes).
// LI=0, VN=3, Mode=3 (client) → first byte = 0x1B.
var ntpRequest = func() []byte {
	b := make([]byte, 48)
	b[0] = 0x1B
	return b
}()

func (p *NTPProber) Probe(ctx context.Context, ip string, port uint16) (*ProbeResult, error) {
	addr := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("udp", addr, p.timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(p.timeout))

	if _, err := conn.Write(ntpRequest); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}

	resp := make([]byte, 48)
	n, err := conn.Read(resp)
	if err != nil || n < 48 {
		return nil, fmt.Errorf("invalid ntp response")
	}

	// Validate: LI/VN/Mode byte — mode must be 4 (server)
	mode := resp[0] & 0x07
	if mode != 4 {
		return nil, fmt.Errorf("not ntp: mode=%d", mode)
	}
	return &ProbeResult{IP: ip, Port: port, AppProto: "ntp", Banner: "NTP", Timestamp: time.Now()}, nil
}
