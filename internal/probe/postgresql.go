package probe

import (
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// PostgreSQLProber identifies PostgreSQL services and extracts the server version.
type PostgreSQLProber struct{ timeout time.Duration }

func NewPostgreSQLProber(timeout time.Duration) *PostgreSQLProber {
	return &PostgreSQLProber{timeout}
}
func (p *PostgreSQLProber) Protocol() string             { return "postgresql" }
func (p *PostgreSQLProber) ShouldProbe(port uint16) bool { return port == 5432 }

// pgStartup is a minimal PostgreSQL startup message (protocol 3.0).
var pgStartup = func() []byte {
	user := []byte("user\x00zeye\x00\x00")
	msg := make([]byte, 4+4+len(user))
	binary.BigEndian.PutUint32(msg[0:], uint32(len(msg)))
	binary.BigEndian.PutUint32(msg[4:], 196608) // protocol 3.0
	copy(msg[8:], user)
	return msg
}()

func (p *PostgreSQLProber) Probe(ctx context.Context, ip string, port uint16) (*ProbeResult, error) {
	conn, err := dialTCP(ctx, ip, port)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(p.timeout))

	if _, err := conn.Write(pgStartup); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}

	// Read the first message to confirm PostgreSQL identity.
	msgType, _, err := pgReadMessage(conn)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	// Valid first responses: 'R' (Authentication), 'E' (Error)
	if msgType != 'R' && msgType != 'E' {
		return nil, fmt.Errorf("not postgresql: type=%c", msgType)
	}

	// Continue reading messages looking for ParameterStatus ('S') with server_version.
	version := ""
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	for version == "" {
		mt, mb, err := pgReadMessage(conn)
		if err != nil {
			break
		}
		if mt == 'S' {
			// ParameterStatus: name_cstring + value_cstring
			parts := pgSplitCStrings(mb)
			if len(parts) == 2 && parts[0] == "server_version" {
				version = parts[1]
			}
		}
		// Stop after ReadyForQuery or unknown message type
		if mt == 'Z' || mt == 'E' {
			break
		}
	}

	banner := "PostgreSQL"
	if version != "" {
		banner = "PostgreSQL " + version
	}
	return &ProbeResult{
		IP: ip, Port: port, AppProto: "postgresql", Banner: banner, Timestamp: time.Now(),
	}, nil
}

// pgReadMessage reads one PostgreSQL wire protocol message.
// Format: byte type + int32 length (including itself) + body
func pgReadMessage(conn interface {
	Read([]byte) (int, error)
}) (byte, []byte, error) {
	header := make([]byte, 5)
	if _, err := readFullFromReader(conn, header); err != nil {
		return 0, nil, err
	}
	msgType := header[0]
	msgLen := int(binary.BigEndian.Uint32(header[1:])) - 4 // length field includes itself
	if msgLen < 0 || msgLen > 65536 {
		return msgType, nil, nil
	}
	body := make([]byte, msgLen)
	if _, err := readFullFromReader(conn, body); err != nil {
		return msgType, nil, err
	}
	return msgType, body, nil
}

func readFullFromReader(r interface{ Read([]byte) (int, error) }, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := r.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// pgSplitCStrings splits a byte slice of null-terminated C strings.
func pgSplitCStrings(data []byte) []string {
	var parts []string
	for len(data) > 0 {
		idx := strings.IndexByte(string(data), 0)
		if idx < 0 {
			parts = append(parts, string(data))
			break
		}
		parts = append(parts, string(data[:idx]))
		data = data[idx+1:]
	}
	return parts
}
