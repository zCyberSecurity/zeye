package probe

import (
	"bufio"
	"context"
	"fmt"
	"strings"
	"time"
)

// RedisProber identifies Redis services and extracts the server version.
type RedisProber struct{ timeout time.Duration }

func NewRedisProber(timeout time.Duration) *RedisProber { return &RedisProber{timeout} }
func (p *RedisProber) Protocol() string                 { return "redis" }
func (p *RedisProber) ShouldProbe(port uint16) bool     { return port == 6379 || port == 6380 }

func (p *RedisProber) Probe(ctx context.Context, ip string, port uint16) (*ProbeResult, error) {
	conn, err := dialTCP(ctx, ip, port)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(p.timeout))

	// Step 1: PING to confirm Redis identity.
	if _, err := conn.Write([]byte("PING\r\n")); err != nil {
		return nil, fmt.Errorf("write ping: %w", err)
	}
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("read ping: %w", err)
	}
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "$") {
		return nil, fmt.Errorf("not redis: %q", line)
	}

	authRequired := strings.HasPrefix(line, "-")

	// Step 2: INFO server to get version (skip if auth is required).
	version := ""
	if !authRequired {
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := conn.Write([]byte("INFO server\r\n")); err == nil {
			version = readRedisVersion(reader)
		}
	}

	banner := "Redis"
	if version != "" {
		banner = "Redis " + version
	}
	if authRequired {
		banner = "Redis (auth required)"
	}
	return &ProbeResult{
		IP: ip, Port: port, AppProto: "redis", Banner: banner, Timestamp: time.Now(),
	}, nil
}

// readRedisVersion reads a Redis bulk string response and extracts redis_version.
func readRedisVersion(r *bufio.Reader) string {
	// Bulk string: $<len>\r\n<data>\r\n
	header, err := r.ReadString('\n')
	if err != nil || !strings.HasPrefix(header, "$") {
		return ""
	}
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "redis_version:") {
			return strings.TrimPrefix(line, "redis_version:")
		}
		// End of INFO section
		if line == "" {
			break
		}
	}
	return ""
}
