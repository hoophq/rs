// Command hooprs scans local AI coding sessions (Claude Code, Cursor,
// OpenCode) for PII and secrets entirely on the machine (no gateway, no
// network) and renders a risk summary to the terminal and a self-contained
// HTML report.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hoophq/alcatraz/anonymizer"
	"github.com/hoophq/rs/analyze"
	"github.com/hoophq/rs/guardrails"
	"github.com/hoophq/rs/report"
	"github.com/hoophq/rs/risk"
	"github.com/hoophq/rs/sources"
	"github.com/hoophq/rs/state"
	"github.com/hoophq/rs/types"
)

// version is the build version, overridden at release time via
// -ldflags "-X main.version=vX.Y.Z" (see npm/build.mjs). Unstamped local builds
// report "dev".
var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "hooprs: %v\n", err)
		os.Exit(1)
	}
}

type options struct {
	out         string
	jsonOut     string
	tools       string
	project     string
	session     string
	days        int
	home        string
	rules       string
	statePath   string
	minScore    float64
	critWeight  float64
	engine      string
	ner         bool
	workers     int
	incremental bool
	quiet       bool
	open        bool
	showValues  bool
	maskValues  bool
	showVersion bool
}

func run() error {
	defaultHome, _ := os.UserHomeDir()
	opt := options{}
	flag.StringVar(&opt.out, "out", "risk-report.html", "path to write the self-contained HTML report")
	flag.StringVar(&opt.jsonOut, "json", "", "also write the machine-readable risk report to this path")
	flag.StringVar(&opt.tools, "tools", "claude,cursor,opencode", "comma-separated sources to scan")
	flag.StringVar(&opt.project, "project", "", "only scan sessions whose project matches this regexp")
	flag.StringVar(&opt.session, "session", "", "only scan sessions whose id matches this regexp")
	flag.IntVar(&opt.days, "days", 0, "only scan sessions started within the last N days (0 = all time)")
	flag.StringVar(&opt.home, "home", defaultHome, "home directory to discover sessions under")
	flag.StringVar(&opt.rules, "rules", "", "path to a guardrails rules JSON file (optional)")
	flag.StringVar(&opt.statePath, "state", filepath.Join(defaultHome, ".risk-analyzer", "state.json"), "incremental scan state file")
	flag.Float64Var(&opt.minScore, "min-score", 0.4, "minimum detection confidence (0-1) for a finding to count")
	flag.Float64Var(&opt.critWeight, "critical-weight", risk.DefaultCriticalWeight, "security-score penalty weight (0-100) for the critical-session share")
	flag.StringVar(&opt.engine, "engine", "alcatraz", "detection engine: alcatraz (default, full PII set) or stub (zero-dependency fallback)")
	flag.BoolVar(&opt.ner, "ner", false, "run the statistical NER model to detect PERSON and LOCATION entities (alcatraz engine only; downloads the ONNX model on first use and adds significant scan time on large histories)")
	flag.IntVar(&opt.workers, "workers", 0, "number of parallel analysis workers (0 = one per CPU core)")
	flag.BoolVar(&opt.incremental, "incremental", false, "only scan content appended since the last run (persists offsets)")
	flag.BoolVar(&opt.quiet, "quiet", false, "do not print the terminal summary")
	flag.BoolVar(&opt.showValues, "show-values", false, "print the matched high-severity values for the top 10 critical sessions in the terminal summary (sensitive; never written to the HTML/JSON reports)")
	flag.BoolVar(&opt.maskValues, "mask-values", false, "like -show-values but each value is masked to its last 4 characters, so the summary can be shared without re-leaking")
	flag.BoolVar(&opt.open, "open", true, "open the HTML report in the default browser when done")
	flag.BoolVar(&opt.showVersion, "version", false, "print the hooprs version and exit")
	flag.Parse()

	if opt.showVersion {
		fmt.Println(version)
		return nil
	}

	if opt.home == "" {
		return fmt.Errorf("could not determine home directory; pass -home")
	}
	if opt.critWeight <= 0 || opt.critWeight > 100 {
		return fmt.Errorf("-critical-weight must be greater than 0 and at most 100, got %v", opt.critWeight)
	}
	if opt.showValues && opt.maskValues {
		return fmt.Errorf("-show-values and -mask-values are mutually exclusive")
	}
	if opt.workers < 0 {
		return fmt.Errorf("-workers must be 0 (auto) or positive, got %d", opt.workers)
	}
	if opt.workers == 0 {
		opt.workers = runtime.NumCPU()
	}
	fmt.Fprintf(os.Stderr, "hooprs: using %d workers\n", opt.workers)

	projectFilter, err := compileFilter(opt.project, "project")
	if err != nil {
		return err
	}
	sessionFilter, err := compileFilter(opt.session, "session")
	if err != nil {
		return err
	}

	srcs, sourceLabels, err := selectSources(opt.tools, opt.home)
	if err != nil {
		return err
	}

	engine, err := loadGuardrails(opt.rules)
	if err != nil {
		return err
	}

	// Full snapshot by default (an in-memory, empty state makes the sources
	// read everything). Incremental mode loads and persists real offsets.
	st := state.NewMemory()
	if opt.incremental {
		st, err = state.Load(opt.statePath)
		if err != nil {
			return fmt.Errorf("loading state: %w", err)
		}
	}

	sessions, err := discover(srcs, st)
	if err != nil {
		return err
	}
	sessions = filterSessions(sessions, projectFilter, sessionFilter, opt.days)

	if opt.ner {
		fmt.Fprintln(os.Stderr, "hooprs: warning: NER adds significant scan time on large histories; a -tags ORT build with HOOPRS_NER_BACKEND=ort is ~10x faster (see README)")
	}
	analyzer, err := buildAnalyzer(opt.engine, opt.minScore, opt.ner)
	if err != nil {
		return err
	}
	// The NER-backed engine owns a model runtime that must be released.
	if closer, ok := analyzer.(io.Closer); ok {
		defer closer.Close()
	}
	inputs := analyzeSessions(analyzer, engine, sessions, valueCapture(opt), opt.workers)

	rep := risk.Build(risk.Meta{
		GeneratedAt:    time.Now(),
		Sources:        sourceLabels,
		WindowDays:     opt.days,
		CriticalWeight: opt.critWeight,
		ValuesMasked:   opt.maskValues,
	}, inputs)

	if err := writeHTML(opt.out, rep); err != nil {
		return err
	}
	if opt.jsonOut != "" {
		if err := writeJSON(opt.jsonOut, rep); err != nil {
			return err
		}
	}
	if opt.incremental {
		if err := commitState(st, sessions); err != nil {
			return fmt.Errorf("saving state: %w", err)
		}
	}

	if !opt.quiet {
		report.Terminal(os.Stdout, rep)
	}
	fmt.Printf("HTML report written to %s\n", opt.out)
	if opt.jsonOut != "" {
		fmt.Printf("JSON report written to %s\n", opt.jsonOut)
	}

	// Opening the browser is a convenience, not a guarantee: a missing opener
	// (headless box, no $DISPLAY) must not fail an otherwise-successful scan.
	if opt.open {
		if err := openBrowser(opt.out); err != nil {
			fmt.Fprintf(os.Stderr, "hooprs: could not open browser (report is at %s): %v\n", opt.out, err)
		}
	}
	return nil
}

// openBrowser launches the OS default handler for path (the generated HTML
// report). It returns as soon as the handler is spawned and does not wait for
// the browser to exit.
func openBrowser(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", abs)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", abs)
	default:
		cmd = exec.Command("xdg-open", abs)
	}
	return cmd.Start()
}

// buildAnalyzer constructs the detection engine named by -engine. alcatraz (the
// default) pairs the alcatraz library's structured-PII recognizers with the
// local secrets pack, optionally plus the statistical NER model; stub is the
// zero-dependency regex fallback. Both seed their confidence threshold from
// minScore.
//
// NER is opt-in, so useNER always records an explicit request: a model that
// fails to initialize (offline first run, corrupted model cache, missing
// backend build tag) is a hard error, never a silent downgrade to
// pattern-only detection.
func buildAnalyzer(name string, minScore float64, useNER bool) (analyze.Analyzer, error) {
	switch name {
	case "alcatraz", "":
		var a *analyze.Alcatraz
		if useNER {
			fmt.Fprintln(os.Stderr, "hooprs: loading NER model (downloaded on first use) …")
			var err error
			a, err = analyze.NewAlcatrazNER(context.Background())
			if err != nil {
				return nil, err
			}
		} else {
			a = analyze.NewAlcatraz()
		}
		a.SetThreshold(minScore)
		return a, nil
	case "stub":
		if useNER {
			return nil, fmt.Errorf("-ner requires the alcatraz engine")
		}
		a := analyze.NewStub()
		a.SetThreshold(minScore)
		return a, nil
	default:
		return nil, fmt.Errorf("unknown -engine %q (want alcatraz or stub)", name)
	}
}

func compileFilter(expr, name string) (*regexp.Regexp, error) {
	if expr == "" {
		return nil, nil
	}
	re, err := regexp.Compile(expr)
	if err != nil {
		return nil, fmt.Errorf("invalid -%s filter %q: %w", name, expr, err)
	}
	return re, nil
}

func selectSources(tools, home string) ([]sources.Source, []string, error) {
	enabled := map[string]bool{}
	for _, t := range strings.Split(tools, ",") {
		t = strings.TrimSpace(t)
		if t != "" {
			enabled[t] = true
		}
	}
	var srcs []sources.Source
	var labels []string
	if enabled["claude"] {
		srcs = append(srcs, sources.NewClaude(home))
		labels = append(labels, "~/.claude")
		delete(enabled, "claude")
	}
	if enabled["cursor"] {
		srcs = append(srcs, sources.NewCursor(home))
		labels = append(labels, "~/.cursor")
		delete(enabled, "cursor")
	}
	if enabled["opencode"] {
		srcs = append(srcs, sources.NewOpenCode(home))
		labels = append(labels, "~/.local/share/opencode")
		delete(enabled, "opencode")
	}
	for unknown := range enabled {
		return nil, nil, fmt.Errorf("unknown source %q (want claude, cursor or opencode)", unknown)
	}
	if len(srcs) == 0 {
		return nil, nil, fmt.Errorf("no sources selected")
	}
	return srcs, labels, nil
}

func loadGuardrails(path string) (*guardrails.Engine, error) {
	if path == "" {
		return nil, nil
	}
	engine, err := guardrails.Load(path)
	if err != nil {
		return nil, fmt.Errorf("loading guardrails: %w", err)
	}
	return engine, nil
}

func discover(srcs []sources.Source, st *state.State) ([]types.Session, error) {
	var all []types.Session
	for _, src := range srcs {
		found, err := src.Discover(st)
		if err != nil {
			return nil, fmt.Errorf("discovering %s sessions: %w", src.Name(), err)
		}
		all = append(all, found...)
	}
	return all, nil
}

func filterSessions(sessions []types.Session, project, session *regexp.Regexp, days int) []types.Session {
	var cutoff time.Time
	if days > 0 {
		cutoff = time.Now().AddDate(0, 0, -days)
	}
	var kept []types.Session
	for _, s := range sessions {
		if project != nil && !project.MatchString(s.Project) {
			continue
		}
		if session != nil && !session.MatchString(s.ID) {
			continue
		}
		if days > 0 && !s.StartedAt.IsZero() && s.StartedAt.Before(cutoff) {
			continue
		}
		kept = append(kept, s)
	}
	return kept
}

// capture describes whether and how matched values are kept for the terminal
// summary. transform is nil for raw values (-show-values) and an anonymizer
// operator for masked ones (-mask-values).
type capture struct {
	enabled   bool
	transform anonymizer.Operator
}

// valueCapture derives the capture mode from the flags: raw values with
// -show-values, values masked to their last 4 runes with -mask-values, and no
// capture at all by default.
func valueCapture(opt options) capture {
	switch {
	case opt.showValues:
		return capture{enabled: true}
	case opt.maskValues:
		return capture{enabled: true, transform: anonymizer.MaskKeepLast('*', 4)}
	default:
		return capture{}
	}
}

// progress renders a single-line, in-place counter on stderr while the scan
// runs. It stays silent when stderr is not a terminal (piped or redirected
// runs get no control-character junk) and when there is nothing to count.
// step is safe to call from concurrent workers.
//
// The percentage is weighted by bytes, not messages: analysis cost is
// proportional to text length, and messages are processed shortest-first, so
// a message-count percentage sprints through the cheap majority and then
// looks frozen on the few large messages that hold most of the actual work.
type progress struct {
	enabled    bool
	total      int
	totalBytes int
	started    time.Time

	mu        sync.Mutex
	done      int
	doneBytes int
	last      time.Time
}

func newProgress(total, totalBytes int) *progress {
	info, err := os.Stderr.Stat()
	isTerminal := err == nil && info.Mode()&os.ModeCharDevice != 0
	return &progress{
		enabled:    isTerminal && total > 0,
		total:      total,
		totalBytes: totalBytes,
		started:    time.Now(),
	}
}

// step advances the counter by n messages totalling bytes of analyzed text.
// Redraws are throttled so terminal writes never become the bottleneck of a
// fast scan.
func (p *progress) step(n, bytes int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.done += n
	p.doneBytes += bytes
	if !p.enabled || (time.Since(p.last) < 100*time.Millisecond && p.done < p.total) {
		return
	}
	p.last = time.Now()
	percent := 0
	if p.totalBytes > 0 {
		percent = p.doneBytes * 100 / p.totalBytes
	} else if p.total > 0 {
		percent = p.done * 100 / p.total
	}
	fmt.Fprintf(os.Stderr, "\rhooprs: analyzing messages … %d/%d · %s (%d%%)",
		p.done, p.total, byteRatio(p.doneBytes, p.totalBytes), percent)
}

// finish replaces the counter with a completion line, padded to overwrite the
// widest progress render.
func (p *progress) finish() {
	if !p.enabled {
		return
	}
	fmt.Fprintf(os.Stderr, "\rhooprs: analyzed %d messages (%s) in %s%*s\n",
		p.done, byteRatio(p.doneBytes, p.doneBytes),
		time.Since(p.started).Round(time.Millisecond), 24, "")
}

// byteRatio renders "done/total" in a unit sized to total (e.g. "1.2/1.9 MB",
// "412/730 KB"), or just the total when done == total.
func byteRatio(done, total int) string {
	unit, div := "KB", float64(1<<10)
	if total >= 1<<20 {
		unit, div = "MB", float64(1<<20)
	}
	if done == total {
		return fmt.Sprintf("%.1f %s", float64(total)/div, unit)
	}
	return fmt.Sprintf("%.1f/%.1f %s", float64(done)/div, float64(total)/div, unit)
}

// messageResult is the per-message outcome of the parallel analysis phase,
// stored at the message's own slot so aggregation can run in original order.
type messageResult struct {
	findings []analyze.Finding
	matches  []guardrails.Match
	err      error
}

// analyzeSessions runs the detection engine over every message, fanned out
// across workers goroutines (both the alcatraz/NER engine and the guardrail
// matcher are safe for concurrent use). Results land in per-message slots and
// are aggregated sequentially afterwards, so the produced SessionInputs are
// identical to a single-worker run. Matched values are captured into
// SessionInput.Details only when the user opted in (raw or masked); the
// default run aggregates counts and lets the values go.
func analyzeSessions(analyzer analyze.Analyzer, engine *guardrails.Engine, sessions []types.Session, values capture, workers int) []risk.SessionInput {
	totalMessages, totalBytes := 0, 0
	for _, sess := range sessions {
		totalMessages += len(sess.Messages)
		for _, msg := range sess.Messages {
			totalBytes += len(msg.Text)
		}
	}
	prog := newProgress(totalMessages, totalBytes)
	defer prog.finish()

	results := analyzeMessages(analyzer, engine, sessions, workers, prog)

	inputs := make([]risk.SessionInput, 0, len(sessions))
	for si, sess := range sessions {
		in := risk.SessionInput{
			Tool:       sess.Tool,
			ID:         sess.ID,
			Project:    sess.Project,
			StartedAt:  sess.StartedAt,
			Messages:   len(sess.Messages),
			PIISummary: map[string]int64{},
			PIIInput:   map[string]int64{},
			PIIOutput:  map[string]int64{},
		}
		for mi, msg := range sess.Messages {
			res := results[si][mi]
			if res.err != nil {
				fmt.Fprintf(os.Stderr, "hooprs: analyzing %s/%s: %v\n", sess.ID, msg.ID, res.err)
				continue
			}
			direction := msg.Role.GuardrailDirection()
			for _, f := range res.findings {
				in.PIISummary[f.EntityType]++
				if direction == "input" {
					in.PIIInput[f.EntityType]++
				} else {
					in.PIIOutput[f.EntityType]++
				}
				if values.enabled {
					value := f.Value
					if values.transform != nil {
						value = values.transform(f.EntityType, value)
					}
					in.Details = append(in.Details, risk.FindingDetail{Entity: f.EntityType, Value: value})
				}
			}
			for _, m := range res.matches {
				in.Guardrails = append(in.Guardrails, risk.Violation{
					Tool:         sess.Tool,
					SessionID:    sess.ID,
					MessageID:    msg.ID,
					RuleName:     m.RuleName,
					RuleType:     m.RuleType,
					Direction:    m.Direction,
					MatchedWords: m.MatchedWords,
				})
			}
		}
		inputs = append(inputs, in)
	}
	return inputs
}

// Batch limits for the analysis workers. Size amortizes the model's per-call
// overhead; the byte cap keeps a batch of large messages from ballooning the
// padded tensor (every text in a batch is padded to the longest member).
const (
	analysisBatchSize  = 32
	analysisBatchBytes = 64 << 10
)

// analyzeMessages runs detection and guardrail matching over every message
// using a bounded worker pool and returns the results indexed by
// [session][message]. Messages are grouped into length-sorted batches: a
// BatchAnalyzer engine (alcatraz) then runs one model inference per batch
// instead of one per message, and similar-length texts per batch keep the
// padding overhead low. Each result slot is written by exactly one worker, so
// the matrix needs no locking; only the progress counter is shared.
func analyzeMessages(analyzer analyze.Analyzer, engine *guardrails.Engine, sessions []types.Session, workers int, prog *progress) [][]messageResult {
	results := make([][]messageResult, len(sessions))
	total := 0
	for si, sess := range sessions {
		results[si] = make([]messageResult, len(sess.Messages))
		total += len(sess.Messages)
	}

	type ref struct{ si, mi int }
	refs := make([]ref, 0, total)
	for si, sess := range sessions {
		for mi := range sess.Messages {
			refs = append(refs, ref{si, mi})
		}
	}
	text := func(r ref) string { return sessions[r.si].Messages[r.mi].Text }
	sort.SliceStable(refs, func(i, j int) bool { return len(text(refs[i])) < len(text(refs[j])) })

	var batches [][]ref
	var cur []ref
	curBytes := 0
	for _, r := range refs {
		n := len(text(r))
		if len(cur) > 0 && (len(cur) >= analysisBatchSize || curBytes+n > analysisBatchBytes) {
			batches = append(batches, cur)
			cur, curBytes = nil, 0
		}
		cur = append(cur, r)
		curBytes += n
	}
	if len(cur) > 0 {
		batches = append(batches, cur)
	}

	batcher, canBatch := analyzer.(analyze.BatchAnalyzer)
	analyzeOne := func(r ref) messageResult {
		findings, err := analyzer.Analyze(text(r))
		return messageResult{findings: findings, err: err}
	}

	jobs := make(chan []ref)
	var wg sync.WaitGroup
	if workers < 1 {
		workers = 1
	}
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for batch := range jobs {
				if canBatch && len(batch) > 1 {
					texts := make([]string, len(batch))
					for i, r := range batch {
						texts[i] = text(r)
					}
					if findings, err := batcher.AnalyzeBatch(texts); err == nil {
						for i, r := range batch {
							results[r.si][r.mi] = messageResult{findings: findings[i]}
						}
					} else {
						// A failed batch degrades to per-message analysis so
						// one bad batch cannot lose 32 messages of findings.
						for _, r := range batch {
							results[r.si][r.mi] = analyzeOne(r)
						}
					}
				} else {
					for _, r := range batch {
						results[r.si][r.mi] = analyzeOne(r)
					}
				}
				if !engine.Empty() {
					for _, r := range batch {
						if results[r.si][r.mi].err == nil {
							msg := sessions[r.si].Messages[r.mi]
							results[r.si][r.mi].matches = engine.Match(msg.Text, msg.Role.GuardrailDirection())
						}
					}
				}
				batchBytes := 0
				for _, r := range batch {
					batchBytes += len(text(r))
				}
				prog.step(len(batch), batchBytes)
			}
		}()
	}
	for _, b := range batches {
		jobs <- b
	}
	close(jobs)
	wg.Wait()
	return results
}

func writeHTML(path string, rep risk.Report) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating HTML report: %w", err)
	}
	defer f.Close()
	if err := report.HTML(f, rep, version); err != nil {
		return fmt.Errorf("rendering HTML report: %w", err)
	}
	return nil
}

func writeJSON(path string, rep risk.Report) error {
	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding JSON report: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("writing JSON report: %w", err)
	}
	return nil
}

func commitState(st *state.State, sessions []types.Session) error {
	for _, s := range sessions {
		for path, offset := range s.Marks {
			st.Mark(path, offset)
		}
	}
	return st.Save()
}
