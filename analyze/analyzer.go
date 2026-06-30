// Package analyze detects PII and secrets in text. The Analyzer interface is
// the seam between the scanner pipeline and the detection engine: the default
// engine wraps the alcatraz library (structured PII) plus a local secrets pack,
// and a dependency-free regex Stub is available as a fallback. Swapping engines
// requires no change to callers.
package analyze

// defaultThreshold is the minimum confidence a finding must reach to be
// reported. It filters inherently weak signals (e.g. a bare 9-digit number with
// plausible SSN structure) while keeping checksum-validated and high-prefix
// matches. Each engine seeds its threshold here; callers override it via
// SetThreshold.
const defaultThreshold = 0.4

// Finding is a single detected entity. Because detection runs locally there is
// no privacy boundary, so the matched Value is returned directly alongside the
// character offsets.
type Finding struct {
	EntityType string
	Value      string
	Score      float64
	Start      int
	End        int
}

// Analyzer detects entities in a single piece of text.
type Analyzer interface {
	Analyze(text string) ([]Finding, error)
}
