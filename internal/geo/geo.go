package geo

import (
	"fmt"
	"net"
	"sync"

	"github.com/oschwald/geoip2-golang"
)

// DB wraps a MaxMind GeoLite2/GeoIP2 City database.
type DB struct {
	reader *geoip2.Reader
	mu     sync.RWMutex
}

// Info holds geographic information for an IP address.
type Info struct {
	Country string // ISO 3166-1 alpha-2 code, e.g. "CN", "US"
	Region  string // subdivision name, e.g. "Beijing", "California"
	City    string // city name
}

// Open opens a MaxMind .mmdb file.
func Open(path string) (*DB, error) {
	reader, err := geoip2.Open(path)
	if err != nil {
		return nil, err
	}
	return &DB{reader: reader}, nil
}

// Close releases the database resources.
func (db *DB) Close() error {
	return db.reader.Close()
}

// Lookup returns geographic info for the given IP string.
func (db *DB) Lookup(ipStr string) (*Info, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP: %s", ipStr)
	}
	db.mu.RLock()
	record, err := db.reader.City(ip)
	db.mu.RUnlock()
	if err != nil {
		return nil, err
	}
	info := &Info{
		Country: record.Country.IsoCode,
		City:    record.City.Names["en"],
	}
	if len(record.Subdivisions) > 0 {
		info.Region = record.Subdivisions[0].Names["en"]
	}
	return info, nil
}
