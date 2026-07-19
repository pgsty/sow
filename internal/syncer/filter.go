package syncer

import (
	"fmt"
	"path"
	"regexp"
	"strings"
)

type Filter struct {
	Allow     []string
	Deny      []string
	DebugInfo string
}

func (f Filter) Validate() error {
	if f.DebugInfo != "" && f.DebugInfo != "keep" && f.DebugInfo != "drop" {
		return fmt.Errorf("debuginfo policy must be keep or drop")
	}
	for _, pattern := range append(append([]string{}, f.Allow...), f.Deny...) {
		if _, err := compilePattern(pattern); err != nil {
			return err
		}
	}
	return nil
}

func (f Filter) Match(name, arch string, debugInfo bool) bool {
	if debugInfo && f.DebugInfo == "drop" {
		return false
	}
	value := name + "@" + arch
	if matchesPatterns(f.Deny, value, name) {
		return false
	}
	return len(f.Allow) == 0 || matchesPatterns(f.Allow, value, name)
}

func matchesPatterns(patterns []string, values ...string) bool {
	for _, pattern := range patterns {
		matcher, err := compilePattern(pattern)
		if err != nil {
			return false
		}
		for _, value := range values {
			if matcher(value) {
				return true
			}
		}
	}
	return false
}

func compilePattern(pattern string) (func(string) bool, error) {
	if pattern == "" {
		return nil, fmt.Errorf("filter pattern cannot be empty")
	}
	if strings.HasPrefix(pattern, "re:") {
		expression, err := regexp.Compile(strings.TrimPrefix(pattern, "re:"))
		if err != nil {
			return nil, fmt.Errorf("invalid regex filter %q: %w", pattern, err)
		}
		return expression.MatchString, nil
	}
	if _, err := path.Match(pattern, "probe"); err != nil {
		return nil, fmt.Errorf("invalid glob filter %q: %w", pattern, err)
	}
	return func(value string) bool {
		matched, _ := path.Match(pattern, value)
		return matched
	}, nil
}
