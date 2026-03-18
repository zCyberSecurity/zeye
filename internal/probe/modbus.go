package probe

import (
	"context"
	"encoding/binary"
	"fmt"
	"time"
)

// ModbusProber identifies Modbus TCP services.
// Sends a Read Coil Status (FC=1) request and validates the response frame.
type ModbusProber struct{ timeout time.Duration }

func NewModbusProber(timeout time.Duration) *ModbusProber { return &ModbusProber{timeout} }
func (p *ModbusProber) Protocol() string                  { return "modbus" }
func (p *ModbusProber) ShouldProbe(port uint16) bool      { return port == 502 }

// modbusRequest is a Modbus TCP ADU: Read Coils (FC=1), address 0, quantity 1.
var modbusRequest = []byte{
	0x00, 0x01, // transaction ID
	0x00, 0x00, // protocol ID = 0 (Modbus)
	0x00, 0x06, // length = 6
	0x01,       // unit ID
	0x01,       // function code: read coils
	0x00, 0x00, // starting address
	0x00, 0x01, // quantity = 1
}

func (p *ModbusProber) Probe(ctx context.Context, ip string, port uint16) (*ProbeResult, error) {
	conn, err := dialTCP(ctx, ip, port)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(p.timeout))

	if _, err := conn.Write(modbusRequest); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}

	// Modbus TCP response header is at least 7 bytes (MBAP + function code).
	resp := make([]byte, 9)
	if _, err := readFull(conn, resp); err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}

	// Validate: transaction ID must echo back, protocol ID must be 0.
	txID := binary.BigEndian.Uint16(resp[0:2])
	protoID := binary.BigEndian.Uint16(resp[2:4])
	if txID != 0x0001 || protoID != 0x0000 {
		return nil, fmt.Errorf("not modbus")
	}
	return &ProbeResult{IP: ip, Port: port, AppProto: "modbus", Banner: "Modbus TCP", Timestamp: time.Now()}, nil
}
