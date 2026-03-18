package probe

import (
	"context"
	"fmt"
	"net"
	"time"
)

// MQTTProber identifies MQTT brokers.
// Sends a CONNECT packet (MQTT 3.1.1) and checks for a CONNACK response.
type MQTTProber struct{ timeout time.Duration }

func NewMQTTProber(timeout time.Duration) *MQTTProber { return &MQTTProber{timeout} }
func (p *MQTTProber) Protocol() string                { return "mqtt" }
func (p *MQTTProber) ShouldProbe(port uint16) bool    { return port == 1883 || port == 8883 }

// mqttConnect is a minimal MQTT 3.1.1 CONNECT packet with client ID "zeye".
var mqttConnect = []byte{
	// Fixed header
	0x10, // CONNECT
	0x12, // remaining length = 18
	// Variable header
	0x00, 0x04, 'M', 'Q', 'T', 'T', // protocol name
	0x04,       // protocol level (3.1.1)
	0x02,       // connect flags: clean session
	0x00, 0x3C, // keep alive = 60s
	// Payload: client ID "zeye" (length-prefixed)
	0x00, 0x04, 'z', 'e', 'y', 'e',
}

func (p *MQTTProber) Probe(ctx context.Context, ip string, port uint16) (*ProbeResult, error) {
	var (
		conn net.Conn
		err  error
	)
	if port == 8883 {
		conn, err = dialTLS(ctx, ip, port)
	} else {
		conn, err = dialTCP(ctx, ip, port)
	}
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(p.timeout))

	if _, err := conn.Write(mqttConnect); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}

	resp := make([]byte, 4)
	if _, err := readFull(conn, resp); err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}

	// CONNACK: fixed header 0x20, remaining length 0x02, session present, return code
	if resp[0] != 0x20 || resp[1] != 0x02 {
		return nil, fmt.Errorf("not mqtt: %#v", resp)
	}

	banner := "MQTT"
	if resp[3] == 0x05 {
		banner = "MQTT (auth required)"
	}
	proto := "mqtt"
	if port == 8883 {
		proto = "mqtts"
	}
	r := &ProbeResult{IP: ip, Port: port, AppProto: proto, Banner: banner, Timestamp: time.Now()}
	r.TLSSubject, r.TLSIssuer, r.TLSAltNames, r.TLSExpiry = tlsCertInfo(conn)
	return r, nil
}
