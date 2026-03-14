package query

import (
	"fmt"
	"strconv"
	"strings"
)

// Translate converts an AST into an Elasticsearch Query DSL.
func Translate(node Node) (*TranslateResult, error) {
	t := &translator{}
	dsl, err := t.translate(node)
	if err != nil {
		return nil, err
	}
	return &TranslateResult{DSL: dsl}, nil
}

type translator struct{}

// esFieldMap maps query field names to Elasticsearch field names.
var esFieldMap = map[string]string{
	"ip":            "ip",
	"port":          "port",
	"proto":         "proto",
	"app_proto":     "app_proto",
	"protocol":      "app_proto",
	"title":         "title",
	"status_code":   "status_code",
	"status":        "status_code",
	"server":        "server",
	"body":          "body",
	"banner":        "banner",
	"headers":       "headers",
	"header":        "headers",
	"tls_subject":   "tls_subject",
	"tls.subject":   "tls_subject",
	"cert":          "tls_subject",
	"tls_issuer":    "tls_issuer",
	"tls.issuer":    "tls_issuer",
	"tls_alt_names": "tls_alt_names",
	"tls.alt_names": "tls_alt_names",
	"tls_expiry":    "tls_expiry",
	"first_seen":    "first_seen",
	"last_seen":     "last_seen",
	"scan_count":    "scan_count",
	"fingerprint":   "fingerprints",
	"fingerprints":  "fingerprints",
	"app":           "fingerprints",
	"tag":           "tags",
	"tags":          "tags",
}

// numericFields require integer parsing.
var numericFields = map[string]bool{
	"port": true, "status_code": true, "scan_count": true,
}

// dateFields use date range queries.
var dateFields = map[string]bool{
	"first_seen": true, "last_seen": true, "tls_expiry": true,
}

// textFields use full-text match queries for *=.
var textFields = map[string]bool{
	"body": true, "banner": true,
}

func (t *translator) translate(node Node) (map[string]interface{}, error) {
	switch n := node.(type) {
	case *BinaryNode:
		return t.translateBinary(n)
	case *UnaryNode:
		return t.translateUnary(n)
	case *CompareNode:
		return t.translateCompare(n)
	default:
		return nil, fmt.Errorf("unknown node type %T", node)
	}
}

func (t *translator) translateBinary(n *BinaryNode) (map[string]interface{}, error) {
	left, err := t.translate(n.Left)
	if err != nil {
		return nil, err
	}
	right, err := t.translate(n.Right)
	if err != nil {
		return nil, err
	}
	if n.Op == "AND" {
		return map[string]interface{}{
			"bool": map[string]interface{}{
				"must": []interface{}{left, right},
			},
		}, nil
	}
	return map[string]interface{}{
		"bool": map[string]interface{}{
			"should":               []interface{}{left, right},
			"minimum_should_match": 1,
		},
	}, nil
}

func (t *translator) translateUnary(n *UnaryNode) (map[string]interface{}, error) {
	inner, err := t.translate(n.Operand)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"bool": map[string]interface{}{
			"must_not": []interface{}{inner},
		},
	}, nil
}

func (t *translator) translateCompare(n *CompareNode) (map[string]interface{}, error) {
	field := strings.ToLower(n.Field)
	col, ok := esFieldMap[field]
	if !ok {
		return nil, fmt.Errorf("unknown field %q", n.Field)
	}

	switch n.Operator {
	case "=":
		return t.eqQuery(col, n.Value)
	case "!=":
		inner, err := t.eqQuery(col, n.Value)
		if err != nil {
			return nil, err
		}
		return mustNot(inner), nil
	case "*=":
		return t.containsQuery(col, n.Value)
	case "^=":
		return map[string]interface{}{
			"prefix": map[string]interface{}{col: n.Value},
		}, nil
	case "$=":
		return map[string]interface{}{
			"wildcard": map[string]interface{}{col: map[string]interface{}{
				"value":            "*" + n.Value,
				"case_insensitive": true,
			}},
		}, nil
	case "~=":
		return map[string]interface{}{
			"regexp": map[string]interface{}{col: map[string]interface{}{
				"value":            n.Value,
				"case_insensitive": true,
			}},
		}, nil
	case ">", ">=", "<", "<=":
		return t.rangeQuery(col, n.Operator, n.Value)
	default:
		return nil, fmt.Errorf("unsupported operator %q", n.Operator)
	}
}

func (t *translator) eqQuery(col, value string) (map[string]interface{}, error) {
	if numericFields[col] {
		v, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("field %q requires a numeric value, got %q", col, value)
		}
		return map[string]interface{}{"term": map[string]interface{}{col: v}}, nil
	}
	if textFields[col] {
		// Full-text: match_phrase for exact sentence match
		return map[string]interface{}{"match_phrase": map[string]interface{}{col: value}}, nil
	}
	// keyword, ip, date: term query (ES ip type supports CIDR in term natively)
	return map[string]interface{}{"term": map[string]interface{}{col: value}}, nil
}

func (t *translator) containsQuery(col, value string) (map[string]interface{}, error) {
	if textFields[col] || col == "title" {
		// Full-text match on text field
		return map[string]interface{}{"match": map[string]interface{}{col: value}}, nil
	}
	// keyword field: wildcard with case-insensitive flag
	return map[string]interface{}{
		"wildcard": map[string]interface{}{col: map[string]interface{}{
			"value":            "*" + strings.ToLower(value) + "*",
			"case_insensitive": true,
		}},
	}, nil
}

func (t *translator) rangeQuery(col, op, value string) (map[string]interface{}, error) {
	esOp := map[string]string{">": "gt", ">=": "gte", "<": "lt", "<=": "lte"}[op]
	if numericFields[col] {
		v, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("field %q requires a numeric value, got %q", col, value)
		}
		return map[string]interface{}{"range": map[string]interface{}{col: map[string]interface{}{esOp: v}}}, nil
	}
	// date / string range
	return map[string]interface{}{"range": map[string]interface{}{col: map[string]interface{}{esOp: value}}}, nil
}

func mustNot(inner map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"bool": map[string]interface{}{
			"must_not": []interface{}{inner},
		},
	}
}
