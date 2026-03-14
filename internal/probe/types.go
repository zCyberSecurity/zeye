package probe

import "time"

// ProbeResult holds the complete result of probing a single IP:port.
type ProbeResult struct {
	IP       string `json:"ip"`
	Port     uint16 `json:"port"`
	Proto    string `json:"proto"`
	AppProto string `json:"app_proto"`

	// HTTP / HTTPS specific
	StatusCode  int               `json:"status_code,omitempty"`
	Title       string            `json:"title,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Body        string            `json:"body,omitempty"`
	Server      string            `json:"server,omitempty"`
	RedirectURL string            `json:"redirect_url,omitempty"`

	// TLS specific
	TLSSubject  string    `json:"tls_subject,omitempty"`
	TLSIssuer   string    `json:"tls_issuer,omitempty"`
	TLSAltNames []string  `json:"tls_alt_names,omitempty"`
	TLSExpiry   time.Time `json:"tls_expiry,omitempty"`

	// Generic
	Banner    string    `json:"banner,omitempty"`
	Timestamp time.Time `json:"timestamp"`
	Error     string    `json:"error,omitempty"`
}
