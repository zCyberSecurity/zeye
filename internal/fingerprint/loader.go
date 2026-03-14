package fingerprint

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed rules/*.yaml
var embeddedRules embed.FS

// LoadRules loads fingerprint rules from a directory.
// If dir is empty, the embedded rules are used.
func LoadRules(dir string) ([]*Rule, error) {
	if dir == "" {
		return loadEmbedded()
	}
	return loadFromDir(dir)
}

func loadEmbedded() ([]*Rule, error) {
	var all []*Rule
	err := fs.WalkDir(embeddedRules, "rules", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return nil
		}
		data, err := embeddedRules.ReadFile(path)
		if err != nil {
			return err
		}
		rules, err := parseRuleFile(data)
		if err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		all = append(all, rules...)
		return nil
	})
	return all, err
}

func loadFromDir(dir string) ([]*Rule, error) {
	var all []*Rule
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rules, err := parseRuleFile(data)
		if err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		all = append(all, rules...)
		return nil
	})
	return all, err
}

func parseRuleFile(data []byte) ([]*Rule, error) {
	// Support both single rule and array of rules in one file
	var rules []*Rule
	if err := yaml.Unmarshal(data, &rules); err != nil {
		// Try single rule
		var rule Rule
		if err2 := yaml.Unmarshal(data, &rule); err2 != nil {
			return nil, err
		}
		rules = []*Rule{&rule}
	}
	return rules, nil
}
