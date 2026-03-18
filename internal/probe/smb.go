package probe

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"time"
)

// SMBProber identifies SMB/CIFS services on port 445.
// It sends an SMBv1 Negotiate Protocol Request and checks the response
// for the SMB magic bytes (0xFF 'S' 'M' 'B' or 0xFE 'S' 'M' 'B' for SMBv2).
type SMBProber struct{ timeout time.Duration }

func NewSMBProber(timeout time.Duration) *SMBProber { return &SMBProber{timeout} }
func (p *SMBProber) Protocol() string               { return "smb" }
func (p *SMBProber) ShouldProbe(port uint16) bool   { return port == 445 || port == 139 }

// smbNegotiate is a minimal SMBv1 Negotiate Protocol Request wrapped in a
// NetBIOS Session Service header (required for TCP transport).
var smbNegotiate = []byte{
	// NetBIOS Session Service header
	0x00,             // type: session message
	0x00, 0x00, 0x2F, // length: 47 bytes
	// SMB header
	0xFF, 0x53, 0x4D, 0x42, // magic: \xFFSMB
	0x72,                   // command: negotiate
	0x00, 0x00, 0x00, 0x00, // status
	0x00,                   // flags
	0x00, 0x00,             // flags2
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // pid-high, sig, reserved, tid, pid-low, uid, mid
	// Parameters
	0x00, // word count = 0
	// Data
	0x0C, 0x00, // byte count = 12
	0x02, 0x4E, 0x54, 0x20, 0x4C, 0x4D, 0x20, 0x30, 0x2E, 0x31, 0x32, 0x00, // "NT LM 0.12\0"
}

func (p *SMBProber) Probe(ctx context.Context, ip string, port uint16) (*ProbeResult, error) {
	conn, err := dialTCP(ctx, ip, port)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(p.timeout))

	if _, err := conn.Write(smbNegotiate); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}

	resp := make([]byte, 256)
	n, err := io.ReadAtLeast(conn, resp, 8)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	resp = resp[:n]

	// NetBIOS header is 4 bytes; SMB magic starts at offset 4.
	smb1Magic := []byte{0xFF, 0x53, 0x4D, 0x42}
	smb2Magic := []byte{0xFE, 0x53, 0x4D, 0x42}
	if len(resp) < 8 {
		return nil, fmt.Errorf("response too short")
	}
	body := resp[4:]
	if !bytes.HasPrefix(body, smb1Magic) && !bytes.HasPrefix(body, smb2Magic) {
		return nil, fmt.Errorf("not smb")
	}

	proto := "smb"
	if bytes.HasPrefix(body, smb2Magic) {
		proto = "smb2"
	}
	return &ProbeResult{IP: ip, Port: port, AppProto: proto, Banner: "SMB", Timestamp: time.Now()}, nil
}
