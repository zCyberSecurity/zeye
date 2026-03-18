package probe

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

func dialTCP(ctx context.Context, ip string, port uint16) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", ip, port))
}

func dialTLS(ctx context.Context, ip string, port uint16) (net.Conn, error) {
	d := &net.Dialer{}
	raw, err := d.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, ServerName: ip})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	return tlsConn, nil
}

// readFull reads exactly len(buf) bytes from conn.
func readFull(conn net.Conn, buf []byte) (int, error) {
	return io.ReadFull(conn, buf)
}

// tlsCertInfo extracts subject, issuer, alt-names and expiry from the first
// peer certificate on conn. Returns zero values if conn is not a *tls.Conn
// or no certificates were presented.
func tlsCertInfo(conn net.Conn) (subject, issuer string, altNames []string, expiry time.Time) {
	tc, ok := conn.(*tls.Conn)
	if !ok {
		return
	}
	certs := tc.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return
	}
	cert := certs[0]
	subject = cert.Subject.String()
	issuer = cert.Issuer.String()
	expiry = cert.NotAfter
	altNames = certAltNames(cert)
	return
}

func certAltNames(cert *x509.Certificate) []string {
	var names []string
	names = append(names, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		names = append(names, ip.String())
	}
	return names
}

// bsonString scans a raw BSON byte slice for the first occurrence of a UTF-8
// string element with the given key and returns its value.
// Element encoding: 0x02 + key_cstring + int32_len + string_data + 0x00
func bsonString(data []byte, key string) string {
	needle := append([]byte{0x02}, append([]byte(key), 0x00)...)
	idx := bytes.Index(data, needle)
	if idx < 0 {
		return ""
	}
	idx += len(needle)
	if idx+4 > len(data) {
		return ""
	}
	strLen := int(binary.LittleEndian.Uint32(data[idx:]))
	idx += 4
	if strLen <= 1 || idx+strLen > len(data) {
		return ""
	}
	return string(data[idx : idx+strLen-1]) // exclude null terminator
}
