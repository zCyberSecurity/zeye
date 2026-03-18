package probe

import (
	"context"
	"fmt"
	"time"
)

// OracleProber identifies Oracle Database services via the TNS protocol.
// Sends a TNS Connect packet and checks for a valid TNS response header.
type OracleProber struct{ timeout time.Duration }

func NewOracleProber(timeout time.Duration) *OracleProber { return &OracleProber{timeout} }
func (p *OracleProber) Protocol() string                  { return "oracle" }
func (p *OracleProber) ShouldProbe(port uint16) bool      { return port == 1521 || port == 1522 }

// tnsConnect is a minimal TNS Connect packet requesting a connection to Oracle.
// The connect data is a bare minimum to elicit a RESEND or ACCEPT/REFUSE response.
var tnsConnect = []byte{
	// TNS header
	0x00, 0x3A, // packet length = 58
	0x00, 0x00, // checksum
	0x01,       // type: CONNECT (1)
	0x00,       // flags
	0x00, 0x00, // header checksum
	// Connect data
	0x01, 0x3C, // version (316)
	0x01, 0x2C, // version compatible (300)
	0x00, 0x00, // service options
	0x08, 0x00, // session data unit size (2048)
	0xFF, 0xFF, // max transmission data unit size
	0x7F, 0x08, // NT protocol characteristics
	0x00, 0x00, // line turnaround value
	0x01, 0x00, // value of 1 in hardware
	0x00, 0x20, // length of connect data
	0x00, 0x3A, // offset of connect data
	0x00, 0x00, 0x00, 0x00, // max receivable connect data
	0x00, 0x00, 0x00, 0x00, // connect flags
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	// Connect data (SERVICE_NAME string)
	0x28, 0x41, 0x44, 0x44, 0x52, 0x45, 0x53, 0x53, 0x3D, 0x28, 0x50, 0x52,
	0x4F, 0x54, 0x4F, 0x43, 0x4F, 0x4C, 0x3D, 0x54, 0x43, 0x50, 0x29, 0x29,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}

func (p *OracleProber) Probe(ctx context.Context, ip string, port uint16) (*ProbeResult, error) {
	conn, err := dialTCP(ctx, ip, port)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(p.timeout))

	if _, err := conn.Write(tnsConnect); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}

	resp := make([]byte, 8)
	if _, err := readFull(conn, resp); err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}

	// TNS packet types: 2=ACCEPT, 4=REFUSE, 11=RESEND, 14=MARKER
	pktType := resp[4]
	if pktType != 2 && pktType != 4 && pktType != 11 && pktType != 14 {
		return nil, fmt.Errorf("not oracle: type=%d", pktType)
	}
	return &ProbeResult{IP: ip, Port: port, AppProto: "oracle", Banner: "Oracle TNS", Timestamp: time.Now()}, nil
}
