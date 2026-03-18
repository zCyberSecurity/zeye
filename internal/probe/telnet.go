package probe

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// TelnetProber identifies Telnet services.
// It skips IAC (0xFF) negotiation bytes and extracts any printable banner text.
type TelnetProber struct{ timeout time.Duration }

func NewTelnetProber(timeout time.Duration) *TelnetProber { return &TelnetProber{timeout} }
func (p *TelnetProber) Protocol() string                  { return "telnet" }
func (p *TelnetProber) ShouldProbe(port uint16) bool      { return port == 23 }

func (p *TelnetProber) Probe(ctx context.Context, ip string, port uint16) (*ProbeResult, error) {
	conn, err := dialTCP(ctx, ip, port)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(p.timeout))

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return nil, fmt.Errorf("no data")
	}

	// A Telnet server typically opens with IAC sequences (0xFF).
	// If the first byte is not 0xFF and there's no readable text,
	// this is probably not Telnet.
	raw := buf[:n]
	if raw[0] != 0xFF && !strings.ContainsAny(string(raw), "\r\n") {
		return nil, fmt.Errorf("not telnet")
	}

	banner := stripIAC(raw)
	return &ProbeResult{
		IP: ip, Port: port, AppProto: "telnet", Banner: banner, Timestamp: time.Now(),
	}, nil
}

// stripIAC removes IAC (0xFF) negotiation sequences from Telnet data.
// IAC sequences are: IAC CMD or IAC DO/DONT/WILL/WONT OPTION (3 bytes).
func stripIAC(data []byte) string {
	var out []byte
	i := 0
	for i < len(data) {
		if data[i] == 0xFF && i+1 < len(data) {
			cmd := data[i+1]
			if cmd == 0xFB || cmd == 0xFC || cmd == 0xFD || cmd == 0xFE {
				i += 3 // IAC DO/DONT/WILL/WONT OPTION
			} else {
				i += 2 // IAC CMD
			}
			continue
		}
		out = append(out, data[i])
		i++
	}
	return sanitizeBanner(string(out))
}
