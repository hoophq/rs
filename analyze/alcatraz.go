package analyze

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hoophq/alcatraz/analyzer"
	"github.com/hoophq/alcatraz/ner"
	"github.com/hoophq/alcatraz/recognizers"
	"github.com/knights-analytics/hugot"
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
	// nlp is the statistical NER engine, set only by NewAlcatrazNER. It owns
	// the model runtime and is released by Close.
	nlp *ner.Engine
}

// NewAlcatraz builds an engine with alcatraz's full default recognizer set plus
// the shared secrets pack registered alongside it.
func NewAlcatraz() *Alcatraz {
	return newAlcatraz(nil)
}

// NewAlcatrazNER builds the same engine as NewAlcatraz plus the statistical
// NER recognizer from the alcatraz/ner module, which detects free-text
// entities (PERSON, LOCATION, NRP) that pattern recognizers cannot express.
// The ONNX model is downloaded on first use with progress reported to the
// terminal; ctx bounds that download and the session setup only. Callers must
// release the model runtime with Close.
//
// The inference backend defaults to hugot's pure-Go one, which works in
// every build of hooprs. Binaries compiled with hugot's ORT backend
// ("-tags ORT" plus an ONNX Runtime shared library) can switch to it — and
// to a GPU execution provider — through environment variables:
//
//	HOOPRS_NER_BACKEND=ort           # or xla; empty means pure Go
//	HOOPRS_NER_ORT_LIB=/path/to/lib  # libonnxruntime file or its directory
//	HOOPRS_NER_ACCELERATOR=coreml    # or cuda, directml; empty means CPU
//
// In a build without the matching tag, setting HOOPRS_NER_BACKEND makes the
// engine fail with an error naming the missing build tag.
func NewAlcatrazNER(ctx context.Context) (*Alcatraz, error) {
	modelPath, err := ensureNERModel(ctx)
	if err != nil {
		return nil, fmt.Errorf("obtaining NER model: %w", err)
	}
	nlp, err := ner.New(ctx, ner.Config{
		ModelPath:      modelPath,
		Backend:        os.Getenv("HOOPRS_NER_BACKEND"),
		ORTLibraryPath: os.Getenv("HOOPRS_NER_ORT_LIB"),
		Accelerator:    os.Getenv("HOOPRS_NER_ACCELERATOR"),
	})
	if err != nil {
		return nil, fmt.Errorf("loading NER model: %w", err)
	}
	a := newAlcatraz(nlp.Recognizer("en"))
	// SetNlpEngine makes the engine run the model once per Analyze call and
	// share the artifacts with the NER recognizer.
	a.engine.SetNlpEngine(nlp)
	a.nlp = nlp
	return a, nil
}

func newAlcatraz(extra analyzer.Recognizer) *Alcatraz {
	reg := analyzer.NewRegistry("en")
	recognizers.LoadDefaults(reg, "en")
	for _, rec := range secretRecognizers() {
		reg.Add("en", rec)
	}
	if extra != nil {
		reg.Add("en", extra)
	}
	return &Alcatraz{
		engine:    analyzer.NewEngine(reg, []string{"en"}),
		threshold: defaultThreshold,
	}
}

// AnalyzeBatch implements BatchAnalyzer: it analyzes all texts in one engine
// call, so the NER model (when attached) runs a single batched inference pass
// instead of one per text. Per-text results are identical to Analyze.
func (a *Alcatraz) AnalyzeBatch(texts []string) ([][]Finding, error) {
	threshold := a.threshold
	batches := a.engine.AnalyzeBatch(texts, analyzer.Options{Threshold: &threshold})
	findings := make([][]Finding, len(batches))
	for i, results := range batches {
		findings[i] = toFindings(results)
	}
	return findings, nil
}

// Close releases the NER model runtime, if one was attached. It is a no-op on
// a pattern-only engine.
func (a *Alcatraz) Close() error {
	if a.nlp != nil {
		return a.nlp.Close()
	}
	return nil
}

// ensureNERModel returns the local path of the default NER model, downloading
// it on first use with a progress bar on the terminal. It uses the same cache
// location as the alcatraz/ner module (<user cache>/alcatraz/models), so a
// model fetched by either is found by both; the resulting path is handed to
// ner.New as Config.ModelPath, which skips the module's own silent download.
func ensureNERModel(ctx context.Context) (string, error) {
	model := ner.DefaultConfig().Model
	cache, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(cache, "alcatraz", "models")
	// hugot.DownloadModel stores the model under this derived path; when it is
	// already populated, skip the network entirely.
	modelPath := filepath.Join(dir, strings.ReplaceAll(model, "/", "_"))
	if _, err := os.Stat(filepath.Join(modelPath, "tokenizer.json")); err == nil {
		return modelPath, nil
	}

	opts := hugot.NewDownloadOptions()
	// Verbose renders hugot's download progress ("Downloaded n/m files, X MB")
	// so a first run is not silent for the duration of a ~250 MB download.
	// hugot writes it to stdout, so only enable it when stdout is a terminal —
	// piped or redirected runs keep a clean stream.
	if info, err := os.Stdout.Stat(); err == nil && info.Mode()&os.ModeCharDevice != 0 {
		opts.Verbose = true
	}
	return hugot.DownloadModel(ctx, model, dir, opts)
}

// SetThreshold overrides the minimum confidence a finding must reach to be
// returned (default defaultThreshold).
func (a *Alcatraz) SetThreshold(t float64) { a.threshold = t }

// Analyze runs the engine over text and maps surviving results into Findings,
// dropping the ignored entity types.
func (a *Alcatraz) Analyze(text string) ([]Finding, error) {
	threshold := a.threshold
	results := a.engine.Analyze(text, analyzer.Options{Threshold: &threshold})
	return toFindings(results), nil
}

// toFindings maps engine results into Findings, dropping ignored entity types.
func toFindings(results []analyzer.Result) []Finding {
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
	return findings
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
