// Package analyze detects PII and secrets in text. The Analyzer interface is
// the seam between the scanner pipeline and the detection engine: today it is
// satisfied by a self-contained regex Stub; later it will be satisfied by the
// presidio-go library without any change to callers.
package analyze

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
