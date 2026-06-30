package analyze

import (
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	minScore = 0.0
	maxScore = 1.0
	// defaultThreshold is the minimum confidence a finding must reach to be
	// reported, mirroring Presidio's decision threshold. It filters out the
	// inherently weak signals (e.g. a bare 9-digit number that merely has a
	// plausible SSN structure) while keeping checksum-validated and
	// high-prefix matches.
	defaultThreshold = 0.4
)

// pattern is a compiled regex with a confidence score. group selects which
// capture group locates the entity (0 = the whole match); generic secret
// patterns use group 1 to flag the assigned value rather than the keyword.
type pattern struct {
	re    *regexp.Regexp
	score float64
	group int
}

// recognizer detects one entity type via one or more patterns, with optional
// post-match logic:
//
//   - validate: a true checksum (Luhn, IBAN mod-97). Passing one is strong
//     evidence, so the match is promoted to score 1.0; failing it drops the
//     match. Only use this for actual checksums, never for format plausibility.
//   - filter: a keep/drop predicate that preserves the pattern's own score.
//     Used for format checks (SSN range rules) and the secret heuristics, where
//     passing the check is necessary but not sufficient for full confidence.
//   - sanitize: applied to the matched text before validate/filter (e.g. strip
//     the separators of a credit-card number before the Luhn check).
type recognizer struct {
	entity   string
	patterns []pattern
	validate func(string) bool
	filter   func(string) bool
	sanitize *strings.Replacer
}

// Stub is a dependency-free regex analyzer covering structured PII and the
// secret types that matter most for AI coding sessions. It is the interim
// implementation of Analyzer until presidio-go lands.
type Stub struct {
	recognizers []recognizer
	threshold   float64
}

// SetThreshold overrides the minimum confidence a finding must reach to be
// returned (default defaultThreshold).
func (s *Stub) SetThreshold(t float64) { s.threshold = t }

func pat(expr string, score float64, group int) pattern {
	return pattern{re: regexp.MustCompile(expr), score: score, group: group}
}

// NewStub builds the default recognizer set.
func NewStub() *Stub {
	cardSanitize := strings.NewReplacer("-", "", " ", "")
	return &Stub{recognizers: []recognizer{
		// ── Structured PII ──
		{
			entity:   "EMAIL_ADDRESS",
			patterns: []pattern{pat(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`, 0.7, 0)},
		},
		{
			entity:   "CREDIT_CARD",
			patterns: []pattern{pat(`\b(?:(?:4\d{3})|(?:5[0-5]\d{2})|(?:6\d{3})|(?:3\d{3}))[- ]?\d{3,4}[- ]?\d{3,4}[- ]?\d{3,5}\b`, 0.3, 0)},
			validate: luhnValid,
			sanitize: cardSanitize,
		},
		{
			entity: "US_SSN",
			patterns: []pattern{
				pat(`\b\d{3}-\d{2}-\d{4}\b`, 0.85, 0),
				pat(`\b\d{9}\b`, 0.3, 0),
			},
			// Range rules are a format check, not a checksum: gate, don't
			// promote. The bare 9-digit form stays at 0.3 and is filtered out
			// by the confidence threshold, leaving the dashed form (0.85).
			filter: validSSN,
		},
		{
			entity:   "PHONE_NUMBER",
			patterns: []pattern{pat(`\b\+?\d{0,2}[ .\-]?\(?\d{3}\)?[ .\-]?\d{3}[ .\-]?\d{4}\b`, 0.4, 0)},
		},
		{
			entity:   "IP_ADDRESS",
			patterns: []pattern{pat(`\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b`, 0.6, 0)},
		},
		{
			entity:   "URL",
			patterns: []pattern{pat(`\bhttps?://[^\s<>"'`+"`"+`]+`, 0.5, 0)},
		},
		{
			entity:   "IBAN_CODE",
			patterns: []pattern{pat(`\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b`, 0.4, 0)},
			validate: validIBAN,
		},
		{
			entity:   "CRYPTO",
			patterns: []pattern{pat(`\b(?:bc1[a-zA-HJ-NP-Z0-9]{25,39}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b`, 0.6, 0)},
		},

		// ── Secrets (absent from rs-presidio; the top exposure for coding sessions) ──
		{
			entity:   "AWS_ACCESS_KEY",
			patterns: []pattern{pat(`\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}\b`, 1.0, 0)},
		},
		{
			entity:   "PRIVATE_KEY",
			patterns: []pattern{pat(`-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----`, 1.0, 0)},
		},
		{
			entity: "API_KEY",
			patterns: []pattern{
				pat(`\bgh[pousr]_[A-Za-z0-9]{36}\b`, 1.0, 0),                                        // GitHub
				pat(`\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b`, 0.9, 0),                                 // OpenAI
				pat(`\bAIza[0-9A-Za-z_\-]{35}\b`, 1.0, 0),                                           // Google
				pat(`\bxox[baprs]-[0-9A-Za-z\-]{10,48}\b`, 1.0, 0),                                  // Slack
				pat(`\b(?:sk|rk|pk)_(?:live|test)_[0-9A-Za-z]{16,}\b`, 1.0, 0),                      // Stripe
				pat(`\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b`, 0.7, 0), // JWT
			},
		},
		{
			// Heuristic: a secret-ish keyword assigned a high-entropy value.
			entity:   "API_KEY",
			patterns: []pattern{pat(`(?i)(?:api[_\-]?key|secret|access[_\-]?token|auth[_\-]?token|client[_\-]?secret|token)["']?\s*[:=]\s*["']?([A-Za-z0-9._/+\-]{12,})`, 0.5, 1)},
			filter:   looksLikeSecret,
		},
		{
			entity:   "PASSWORD",
			patterns: []pattern{pat(`(?i)(?:password|passwd|pwd)["']?\s*[:=]\s*["']?([^\s"']{8,})`, 0.5, 1)},
			filter:   looksLikePassword,
		},
	}, threshold: defaultThreshold}
}

// Analyze runs every recognizer over text and returns the deduplicated findings.
func (s *Stub) Analyze(text string) ([]Finding, error) {
	var results []Finding
	for _, rec := range s.recognizers {
		for _, p := range rec.patterns {
			for _, m := range p.re.FindAllStringSubmatchIndex(text, -1) {
				start, end := m[0], m[1]
				if p.group > 0 {
					gi := 2 * p.group
					if gi+1 >= len(m) || m[gi] < 0 {
						continue
					}
					start, end = m[gi], m[gi+1]
				}
				if start < 0 || end <= start {
					continue
				}
				value := text[start:end]
				score := p.score

				candidate := value
				if rec.sanitize != nil {
					candidate = rec.sanitize.Replace(value)
				}
				if rec.filter != nil && !rec.filter(candidate) {
					continue
				}
				if rec.validate != nil {
					if !rec.validate(candidate) {
						continue
					}
					score = maxScore
				}
				if score < s.threshold {
					continue
				}

				results = append(results, Finding{
					EntityType: rec.entity,
					Value:      value,
					Score:      score,
					Start:      start,
					End:        end,
				})
			}
		}
	}
	return dedupe(results), nil
}

// dedupe removes zero-score and same-entity overlapping findings, keeping the
// higher-scoring/wider span (a port of rs-presidio's RecognizerUtils).
func dedupe(results []Finding) []Finding {
	var filtered []Finding
	for _, r := range results {
		if r.Score <= minScore {
			continue
		}
		add := true
		for _, e := range filtered {
			if r.EntityType != e.EntityType {
				continue
			}
			if r.Start == e.Start && r.End == e.End && r.Score <= e.Score {
				add = false
				break
			}
			if r.Start >= e.Start && r.End <= e.End {
				add = false
				break
			}
		}
		if !add {
			continue
		}
		kept := filtered[:0]
		for _, e := range filtered {
			if e.EntityType == r.EntityType && e.Start >= r.Start && e.End <= r.End {
				continue
			}
			kept = append(kept, e)
		}
		filtered = append(kept, r)
	}
	sort.SliceStable(filtered, func(i, j int) bool {
		if filtered[i].Score != filtered[j].Score {
			return filtered[i].Score > filtered[j].Score
		}
		return filtered[i].Start < filtered[j].Start
	})
	return filtered
}

// ── Validators ──

func luhnValid(s string) bool {
	sum, digits := 0, 0
	alt := false
	for i := len(s) - 1; i >= 0; i-- {
		c := s[i]
		if c < '0' || c > '9' {
			continue
		}
		d := int(c - '0')
		digits++
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return digits > 0 && sum%10 == 0
}

func validSSN(s string) bool {
	s = strings.ReplaceAll(s, "-", "")
	if len(s) != 9 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	area, _ := strconv.Atoi(s[0:3])
	group, _ := strconv.Atoi(s[3:5])
	serial, _ := strconv.Atoi(s[5:9])
	if area == 0 || area == 666 || area >= 900 {
		return false
	}
	if group == 0 || serial == 0 {
		return false
	}
	seq, same := true, true
	for i := 1; i < 9; i++ {
		if s[i] != s[i-1]+1 {
			seq = false
		}
		if s[i] != s[i-1] {
			same = false
		}
	}
	return !seq && !same
}

func validIBAN(s string) bool {
	s = strings.ToUpper(strings.ReplaceAll(s, " ", ""))
	if len(s) < 15 || len(s) > 34 {
		return false
	}
	rearranged := s[4:] + s[0:4]
	rem := 0
	for _, c := range rearranged {
		switch {
		case c >= '0' && c <= '9':
			rem = (rem*10 + int(c-'0')) % 97
		case c >= 'A' && c <= 'Z':
			v := int(c-'A') + 10
			rem = (rem*100 + v) % 97
		default:
			return false
		}
	}
	return rem == 1
}

// ── Secret heuristics ──

var secretPlaceholders = []string{
	"xxxx", "redacted", "example", "your-", "your_", "changeme",
	"placeholder", "${", "<", "...", "****", "dummy", "sample", "test",
}

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
