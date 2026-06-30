package analyze

import (
	"github.com/hoophq/alcatraz/analyzer"
	"github.com/hoophq/alcatraz/recognizers"
)

// ignoredEntities are alcatraz detections that are noise for an AI-session risk
// report and never a PII/secret exposure (every log line carries a date). rs
// drops them before findings reach the risk model.
var ignoredEntities = map[string]bool{
	"DATE_TIME": true,
}

// Alcatraz is the default Analyzer. It pairs alcatraz's built-in structured-PII
// recognizers (email, cards, national IDs, IBAN, crypto, ...) with the local
// secrets pack (API keys, private keys, passwords) that alcatraz does not cover.
type Alcatraz struct {
	engine    *analyzer.Engine
	threshold float64
}

// NewAlcatraz builds an engine with alcatraz's full default recognizer set plus
// the shared secrets pack registered alongside it.
func NewAlcatraz() *Alcatraz {
	reg := analyzer.NewRegistry("en")
	recognizers.LoadDefaults(reg, "en")
	for _, rec := range secretRecognizers() {
		reg.Add("en", rec)
	}
	return &Alcatraz{
		engine:    analyzer.NewEngine(reg, []string{"en"}),
		threshold: defaultThreshold,
	}
}

// SetThreshold overrides the minimum confidence a finding must reach to be
// returned (default defaultThreshold).
func (a *Alcatraz) SetThreshold(t float64) { a.threshold = t }

// Analyze runs the engine over text and maps surviving results into Findings,
// dropping the ignored entity types.
func (a *Alcatraz) Analyze(text string) ([]Finding, error) {
	threshold := a.threshold
	results := a.engine.Analyze(text, analyzer.Options{Threshold: &threshold})
	findings := make([]Finding, 0, len(results))
	for _, r := range results {
		if ignoredEntities[r.EntityType] {
			continue
		}
		findings = append(findings, Finding{
			EntityType: r.EntityType,
			Value:      r.Text,
			Score:      r.Score,
			Start:      r.Start,
			End:        r.End,
		})
	}
	return findings, nil
}

// secretRecognizers turns the shared secrets pack (see secrets.go) into alcatraz
// pattern recognizers. A spec's filter becomes a context validator: it inspects
// the matched value (text[start:end]) and keeps or drops the match without
// changing its score, matching the Stub's keep/drop semantics.
func secretRecognizers() []analyzer.Recognizer {
	recs := make([]analyzer.Recognizer, 0, len(secretSpecs))
	for _, s := range secretSpecs {
		pr := analyzer.NewPatternRecognizer(
			s.name, s.entity, "en",
			[]*analyzer.Pattern{analyzer.MustPattern(s.name, s.expr, s.score).WithGroup(s.group)},
		)
		if s.filter != nil {
			filter := s.filter
			pr = pr.WithContextValidator(func(text string, start, end int) bool {
				return filter(text[start:end])
			})
		}
		recs = append(recs, pr)
	}
	return recs
}
