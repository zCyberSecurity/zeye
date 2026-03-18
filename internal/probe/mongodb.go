package probe

import (
	"context"
	"encoding/binary"
	"fmt"
	"time"
)

// MongoDBProber identifies MongoDB services and extracts the server version.
// Sends an OP_QUERY buildInfo command and parses the BSON response.
type MongoDBProber struct{ timeout time.Duration }

func NewMongoDBProber(timeout time.Duration) *MongoDBProber { return &MongoDBProber{timeout} }
func (p *MongoDBProber) Protocol() string                   { return "mongodb" }
func (p *MongoDBProber) ShouldProbe(port uint16) bool       { return port == 27017 }

// mongoBuildInfo is an OP_QUERY for {buildInfo: 1} against admin.$cmd.
// buildInfo response includes a "version" string field.
var mongoBuildInfo = func() []byte {
	// BSON: {buildInfo: 1} — 20 bytes
	bson := []byte{
		0x14, 0x00, 0x00, 0x00, // doc length = 20
		0x10,                                                             // type int32
		0x62, 0x75, 0x69, 0x6C, 0x64, 0x49, 0x6E, 0x66, 0x6F, 0x00,   // "buildInfo\0"
		0x01, 0x00, 0x00, 0x00, // value = 1
		0x00, // doc terminator
	}
	// collection "admin.$cmd\0" — 11 bytes
	coll := []byte{0x61, 0x64, 0x6D, 0x69, 0x6E, 0x2E, 0x24, 0x63, 0x6D, 0x64, 0x00}
	bodyLen := 4 + len(coll) + 4 + 4 + len(bson) // flags + coll + skip + return + bson
	msgLen := 16 + bodyLen
	msg := make([]byte, msgLen)
	binary.LittleEndian.PutUint32(msg[0:], uint32(msgLen))
	binary.LittleEndian.PutUint32(msg[4:], 1)    // requestID
	binary.LittleEndian.PutUint32(msg[8:], 0)    // responseTo
	binary.LittleEndian.PutUint32(msg[12:], 2004) // OP_QUERY
	// flags
	binary.LittleEndian.PutUint32(msg[16:], 0)
	off := 20
	copy(msg[off:], coll)
	off += len(coll)
	binary.LittleEndian.PutUint32(msg[off:], 0) // numberToSkip
	off += 4
	binary.LittleEndian.PutUint32(msg[off:], 1) // numberToReturn
	off += 4
	copy(msg[off:], bson)
	return msg
}()

func (p *MongoDBProber) Probe(ctx context.Context, ip string, port uint16) (*ProbeResult, error) {
	conn, err := dialTCP(ctx, ip, port)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(p.timeout))

	if _, err := conn.Write(mongoBuildInfo); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}

	// Read MsgHeader (16 bytes)
	header := make([]byte, 16)
	if _, err := readFull(conn, header); err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}
	msgLen := binary.LittleEndian.Uint32(header[0:4])
	opCode := binary.LittleEndian.Uint32(header[12:16])
	if opCode != 1 || msgLen < 36 || msgLen > 16*1024*1024 {
		return nil, fmt.Errorf("not mongodb: opCode=%d", opCode)
	}

	// Read OP_REPLY body: 20 bytes fixed fields + BSON documents
	bodyLen := int(msgLen) - 16
	body := make([]byte, bodyLen)
	if _, err := readFull(conn, body); err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	// BSON documents start after the 20-byte OP_REPLY fixed header
	// (responseFlags 4 + cursorID 8 + startingFrom 4 + numberReturned 4)
	version := ""
	if len(body) > 20 {
		version = bsonString(body[20:], "version")
	}

	banner := "MongoDB"
	if version != "" {
		banner = "MongoDB " + version
	}
	return &ProbeResult{
		IP: ip, Port: port, AppProto: "mongodb", Banner: banner, Timestamp: time.Now(),
	}, nil
}
