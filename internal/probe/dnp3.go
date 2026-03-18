package probe

import (
	"context"
	"fmt"
	"time"
)

// DNP3Prober identifies DNP3 (Distributed Network Protocol) services.
// Sends a Link Layer Test request and checks the response for DNP3 start bytes.
type DNP3Prober struct{ timeout time.Duration }

func NewDNP3Prober(timeout time.Duration) *DNP3Prober { return &DNP3Prober{timeout} }
func (p *DNP3Prober) Protocol() string                { return "dnp3" }
func (p *DNP3Prober) ShouldProbe(port uint16) bool    { return port == 20000 }

// dnp3LinkTest is a DNP3 Request Link Status frame with CRC.
// Start bytes: 0x05 0x64, directed to address 0x0000 from 0x0001.
var dnp3LinkTest = []byte{
	0x05, 0x64, // start bytes
	0x05,       // length = 5
	0x9B,       // control: DIR=1, PRM=1, FCB=0, FCV=0, FC=0x1B (REQUEST_LINK_STATES)
	0x00, 0x00, // destination address
	0x01, 0x00, // source address
	0xD0, 0xB0, // CRC
}

func (p *DNP3Prober) Probe(ctx context.Context, ip string, port uint16) (*ProbeResult, error) {
	conn, err := dialTCP(ctx, ip, port)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(p.timeout))

	if _, err := conn.Write(dnp3LinkTest); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}

	resp := make([]byte, 10)
	if _, err := readFull(conn, resp); err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}

	// DNP3 frames always start with 0x05 0x64.
	if resp[0] != 0x05 || resp[1] != 0x64 {
		return nil, fmt.Errorf("not dnp3")
	}
	return &ProbeResult{IP: ip, Port: port, AppProto: "dnp3", Banner: "DNP3", Timestamp: time.Now()}, nil
}
