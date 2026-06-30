package analyze

import (
	"math"
	"strings"
)

// secretSpec is an engine-agnostic definition of a secret pattern: a named
// regex with a confidence score, the entity type it emits, the capture group
// that locates the value (0 = whole match), and an optional keep/drop filter on
// that value. Both detection engines — the alcatraz adapter and the regex Stub —
// build their native recognizers from this one list, so the secrets pack has a
// single source of truth.
type secretSpec struct {
	name   string
	entity string
	expr   string
	score  float64
	group  int
	filter func(string) bool
}

// secretSpecs is the secrets pack: the credential types that dominate exposure
// in AI coding sessions. alcatraz detects none of these (it covers structured
// PII only), so rs supplies them on top of whichever engine is selected.
var secretSpecs = []secretSpec{
	{"aws-access-key", "AWS_ACCESS_KEY", `\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}\b`, 1.0, 0, nil},
	{"private-key", "PRIVATE_KEY", `-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----`, 1.0, 0, nil},
	{"github-token", "API_KEY", `\bgh[pousr]_[A-Za-z0-9]{36}\b`, 1.0, 0, nil},
	{"openai-key", "API_KEY", `\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b`, 0.9, 0, nil},
	{"google-key", "API_KEY", `\bAIza[0-9A-Za-z_\-]{35}\b`, 1.0, 0, nil},
	{"slack-token", "API_KEY", `\bxox[baprs]-[0-9A-Za-z\-]{10,48}\b`, 1.0, 0, nil},
	{"stripe-key", "API_KEY", `\b(?:sk|rk|pk)_(?:live|test)_[0-9A-Za-z]{16,}\b`, 1.0, 0, nil},
	{"jwt", "API_KEY", `\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b`, 0.7, 0, nil},
	{"generic-secret", "API_KEY", `(?i)(?:api[_\-]?key|secret|access[_\-]?token|auth[_\-]?token|client[_\-]?secret|token)["']?\s*[:=]\s*["']?([A-Za-z0-9._/+\-]{12,})`, 0.5, 1, looksLikeSecret},
	{"password-assignment", "PASSWORD", `(?i)(?:password|passwd|pwd)["']?\s*[:=]\s*["']?([^\s"']{8,})`, 0.5, 1, looksLikePassword},
}

// secretPlaceholders are substrings that mark a "secret-looking" value as a
// placeholder rather than a real credential (docs, samples, env templates).
var secretPlaceholders = []string{
	"xxxx", "redacted", "example", "your-", "your_", "changeme",
	"placeholder", "${", "<", "...", "****", "dummy", "sample", "test",
}

// looksLikeSecret gates the generic key=value heuristic: a real secret is long,
// not an obvious placeholder, and has enough entropy to be a random token.
func looksLikeSecret(v string) bool {
	if len(v) < 12 {
		return false
	}
	lv := strings.ToLower(v)
	for _, p := range secretPlaceholders {
		if strings.Contains(lv, p) {
			return false
		}
	}
	return shannon(v) >= 2.5
}

// looksLikePassword gates the password heuristic with a lower length/entropy
// bar than looksLikeSecret, since passwords are shorter than API tokens.
func looksLikePassword(v string) bool {
	if len(v) < 8 {
		return false
	}
	lv := strings.ToLower(v)
	for _, p := range secretPlaceholders {
		if strings.Contains(lv, p) {
			return false
		}
	}
	return shannon(v) >= 2.0
}

// shannon returns the Shannon entropy (bits per symbol) of s.
func shannon(s string) float64 {
	if s == "" {
		return 0
	}
	freq := map[rune]float64{}
	for _, c := range s {
		freq[c]++
	}
	n := 0.0
	for _, c := range freq {
		n += c
	}
	var h float64
	for _, c := range freq {
		p := c / n
		h -= p * math.Log2(p)
	}
	return h
}
