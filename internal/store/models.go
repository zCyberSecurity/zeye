package store

import "time"

// Asset is the central data model for a discovered network asset.
type Asset struct {
	IP           string            `json:"ip"`
	Port         uint16            `json:"port"`
	Proto        string            `json:"proto"`
	AppProto     string            `json:"app_proto"`
	Title        string            `json:"title"`
	StatusCode   int               `json:"status_code"`
	Server       string            `json:"server"`
	Body         string            `json:"body"`
	Headers      map[string]string `json:"headers,omitempty"`
	Banner       string            `json:"banner"`
	TLSSubject   string            `json:"tls_subject"`
	TLSIssuer    string            `json:"tls_issuer"`
	TLSAltNames  []string          `json:"tls_alt_names,omitempty"`
	TLSExpiry    string            `json:"tls_expiry,omitempty"`
	Fingerprints []string          `json:"fingerprints,omitempty"`
	Tags         []string          `json:"tags,omitempty"`
	FirstSeen    *time.Time        `json:"first_seen,omitempty"`
	LastSeen     *time.Time        `json:"last_seen,omitempty"`
	ScanCount    int               `json:"scan_count,omitempty"`
}

// QueryOpts controls result pagination and ordering.
type QueryOpts struct {
	Limit   int
	Offset  int
	OrderBy string // e.g. "last_seen DESC"
}
