// Package guardrails validates session text against a local rules file. Rules
// are direction-aware: input rules check user-typed content, output rules check
// assistant/tool output, mirroring how a proxy validates a live session. The
// gateway used to supply these rules; here they come from a JSON file the user
// controls.
package guardrails

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

// Rule is one guardrail rule as authored in the rules file.
type Rule struct {
	Name string `json:"name"`
	// Type is "regex" or "deny_words".
	Type string `json:"type"`
	// Direction is "input", "output" or "both" (default "both").
	Direction string `json:"direction"`
	// Pattern is the regular expression for Type == "regex".
	Pattern string `json:"pattern"`
	// Words is the deny list for Type == "deny_words".
	Words []string `json:"words"`
}

type ruleset struct {
	Rules []Rule `json:"rules"`
}

type compiledRule struct {
	name      string
	ruleType  string
	direction string
	re        *regexp.Regexp
	words     []string // original-cased, matched case-insensitively
}

// Engine matches text against a compiled set of rules.
type Engine struct {
	rules []compiledRule
}

// Match is a single rule hit.
type Match struct {
	RuleName     string
	RuleType     string
	Direction    string
	MatchedWords []string
}

// Load reads and compiles a JSON rules file.
func Load(path string) (*Engine, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rs ruleset
	if err := json.Unmarshal(data, &rs); err != nil {
		return nil, fmt.Errorf("parsing rules file: %w", err)
	}
	return New(rs.Rules)
}

// New compiles a set of rules into an Engine.
func New(rules []Rule) (*Engine, error) {
	e := &Engine{}
	for _, r := range rules {
		direction := r.Direction
		if direction == "" {
			direction = "both"
		}
		cr := compiledRule{name: r.Name, ruleType: r.Type, direction: direction}
		switch r.Type {
		case "regex":
			re, err := regexp.Compile(r.Pattern)
			if err != nil {
				return nil, fmt.Errorf("rule %q: invalid pattern: %w", r.Name, err)
			}
			cr.re = re
		case "deny_words":
			cr.words = r.Words
		default:
			return nil, fmt.Errorf("rule %q: unknown type %q (want regex or deny_words)", r.Name, r.Type)
		}
		e.rules = append(e.rules, cr)
	}
	return e, nil
}

// Empty reports whether the engine has no rules.
func (e *Engine) Empty() bool { return e == nil || len(e.rules) == 0 }

// Match returns the rules that fire for text in the given direction
// ("input" or "output").
func (e *Engine) Match(text, direction string) []Match {
	if e == nil {
		return nil
	}
	var matches []Match
	lower := strings.ToLower(text)
	for _, r := range e.rules {
		if r.direction != "both" && r.direction != direction {
			continue
		}
		switch r.ruleType {
		case "regex":
			found := uniqueStrings(r.re.FindAllString(text, 8))
			if len(found) > 0 {
				matches = append(matches, Match{RuleName: r.name, RuleType: r.ruleType, Direction: direction, MatchedWords: found})
			}
		case "deny_words":
			var hit []string
			for _, w := range r.words {
				if w != "" && strings.Contains(lower, strings.ToLower(w)) {
					hit = append(hit, w)
				}
			}
			if len(hit) > 0 {
				matches = append(matches, Match{RuleName: r.name, RuleType: r.ruleType, Direction: direction, MatchedWords: uniqueStrings(hit)})
			}
		}
	}
	return matches
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
