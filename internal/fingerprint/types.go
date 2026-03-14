package fingerprint

// Rule is a single fingerprint rule loaded from YAML.
type Rule struct {
	Name           string   `yaml:"name"`
	Category       string   `yaml:"category"`
	Tags           []string `yaml:"tags"`
	VersionPattern string   `yaml:"version_pattern"`
	RequireAll     bool     `yaml:"require_all"`
	MinWeight      int      `yaml:"min_weight"`
	Matches        []Match  `yaml:"matches"`
}

// Match is a single match condition within a rule.
type Match struct {
	ID      string `yaml:"id"`
	Weight  int    `yaml:"weight"`
	Field   string `yaml:"field"`   // header.server, body, title, banner, tls.subject, status_code
	Type    string `yaml:"type"`    // keyword, regex, equals
	Pattern string `yaml:"pattern"` // for regex / keyword
	Value   string `yaml:"value"`   // for equals
}

// MatchResult is the result of fingerprint identification.
type MatchResult struct {
	Name       string
	Category   string
	Version    string
	Tags       []string
	Confidence int // 0–100
}
