package probe

import (
	"context"
	"encoding/binary"
	"fmt"
	"time"
)

// MySQLProber identifies MySQL/MariaDB services.
// Reads the initial server greeting packet and extracts the version string.
type MySQLProber struct{ timeout time.Duration }

func NewMySQLProber(timeout time.Duration) *MySQLProber { return &MySQLProber{timeout} }
func (p *MySQLProber) Protocol() string                 { return "mysql" }
func (p *MySQLProber) ShouldProbe(port uint16) bool     { return port == 3306 || port == 33060 }

func (p *MySQLProber) Probe(ctx context.Context, ip string, port uint16) (*ProbeResult, error) {
	conn, err := dialTCP(ctx, ip, port)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(p.timeout))

	// MySQL packet: 3-byte length + 1-byte sequence number + payload
	header := make([]byte, 4)
	if _, err := readFull(conn, header); err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}
	pktLen := int(binary.LittleEndian.Uint32(append(header[:3], 0)))
	if pktLen == 0 || pktLen > 8192 {
		return nil, fmt.Errorf("invalid packet length: %d", pktLen)
	}

	payload := make([]byte, pktLen)
	if _, err := readFull(conn, payload); err != nil {
		return nil, fmt.Errorf("read payload: %w", err)
	}

	// Byte 0 of payload: protocol version. MySQL uses 10 (0x0A).
	// 0xFF indicates an error packet (e.g. "Host not allowed").
	if payload[0] != 0x0A && payload[0] != 0xFF {
		return nil, fmt.Errorf("not mysql: proto=%d", payload[0])
	}

	// Extract null-terminated version string starting at payload[1].
	version := ""
	if payload[0] == 0x0A && len(payload) > 1 {
		for i := 1; i < len(payload); i++ {
			if payload[i] == 0x00 {
				version = string(payload[1:i])
				break
			}
		}
	}

	banner := "MySQL"
	if version != "" {
		banner = "MySQL " + version
	}
	return &ProbeResult{IP: ip, Port: port, AppProto: "mysql", Banner: banner, Timestamp: time.Now()}, nil
}
