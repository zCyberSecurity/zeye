package fingerprint

import (
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/zCyberSecurity/zeye/internal/probe"
)

// Engine matches fingerprint rules against probe results.
type Engine struct {
	rules []*Rule
}

func NewEngine(rulesDir string) (*Engine, error) {
	rules, err := LoadRules(rulesDir)
	if err != nil {
		return nil, err
	}
	// Precompile regex patterns
	for _, r := range rules {
		if r.MinWeight == 0 {
			r.MinWeight = 1
		}
		for i, m := range r.Matches {
			if m.Weight == 0 {
				r.Matches[i].Weight = 100
			}
		}
	}
	return &Engine{rules: rules}, nil
}

func (e *Engine) RuleCount() int { return len(e.rules) }

// Identify matches all rules against the probe result and returns matches.
func (e *Engine) Identify(result *probe.ProbeResult) []MatchResult {
	if result == nil {
		return nil
	}

	type ruleResult struct {
		match *MatchResult
	}

	resultCh := make(chan ruleResult, len(e.rules))
	var wg sync.WaitGroup

	for _, rule := range e.rules {
		wg.Add(1)
		go func(r *Rule) {
			defer wg.Done()
			m := matchRule(r, result)
			if m != nil {
				resultCh <- ruleResult{match: m}
			}
		}(rule)
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	var results []MatchResult
	for rr := range resultCh {
		if rr.match != nil {
			results = append(results, *rr.match)
		}
	}
	return results
}

func matchRule(rule *Rule, result *probe.ProbeResult) *MatchResult {
	totalWeight := 0
	matchedWeight := 0
	var version string

	for _, m := range rule.Matches {
		fieldVal := extractField(m.Field, result)
		totalWeight += m.Weight

		matched, ver := matchCondition(m, fieldVal)
		if matched {
			matchedWeight += m.Weight
			if ver != "" && version == "" {
				version = ver
			}
		} else if rule.RequireAll {
			return nil // all conditions required; fail fast
		}
	}

	if matchedWeight < rule.MinWeight {
		return nil
	}

	confidence := 100
	if totalWeight > 0 {
		confidence = matchedWeight * 100 / totalWeight
	}

	return &MatchResult{
		Name:       rule.Name,
		Category:   rule.Category,
		Version:    version,
		Tags:       rule.Tags,
		Confidence: confidence,
	}
}

func extractField(field string, result *probe.ProbeResult) string {
	field = strings.ToLower(field)
	switch {
	case strings.HasPrefix(field, "header."):
		headerName := strings.TrimPrefix(field, "header.")
		if result.Headers != nil {
			if v, ok := result.Headers[headerName]; ok {
				return v
			}
		}
		return ""
	case field == "body":
		return result.Body
	case field == "title":
		return result.Title
	case field == "banner":
		return result.Banner
	case field == "server":
		return result.Server
	case field == "tls.subject":
		return result.TLSSubject
	case field == "tls.issuer":
		return result.TLSIssuer
	case field == "status_code":
		return fmt.Sprintf("%d", result.StatusCode)
	case field == "app_proto":
		return result.AppProto
	default:
		return ""
	}
}

func matchCondition(m Match, fieldVal string) (bool, string) {
	if fieldVal == "" {
		return false, ""
	}

	switch strings.ToLower(m.Type) {
	case "keyword":
		pattern := m.Pattern
		if pattern == "" {
			pattern = m.Value
		}
		return strings.Contains(strings.ToLower(fieldVal), strings.ToLower(pattern)), ""

	case "equals":
		v := m.Value
		if v == "" {
			v = m.Pattern
		}
		return strings.EqualFold(fieldVal, v), ""

	case "regex":
		re, err := regexp.Compile("(?i)" + m.Pattern)
		if err != nil {
			return false, ""
		}
		sub := re.FindStringSubmatch(fieldVal)
		if sub == nil {
			return false, ""
		}
		var version string
		if len(sub) > 1 {
			version = sub[1]
		}
		return true, version

	default:
		return false, ""
	}
}
