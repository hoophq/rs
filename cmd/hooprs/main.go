// Command hooprs scans local AI coding sessions (Claude Code, Cursor,
// OpenCode) for PII and secrets entirely on the machine (no gateway, no
// network) and renders a risk summary to the terminal and a self-contained
// HTML report.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

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
	incremental bool
	quiet       bool
	open        bool
	showValues  bool
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
	flag.BoolVar(&opt.incremental, "incremental", false, "only scan content appended since the last run (persists offsets)")
	flag.BoolVar(&opt.quiet, "quiet", false, "do not print the terminal summary")
	flag.BoolVar(&opt.showValues, "show-values", false, "print the matched high-severity values for the top 10 critical sessions in the terminal summary (sensitive; never written to the HTML/JSON reports)")
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

	analyzer, err := buildAnalyzer(opt.engine, opt.minScore)
	if err != nil {
		return err
	}
	inputs := analyzeSessions(analyzer, engine, sessions, opt.showValues)

	rep := risk.Build(risk.Meta{
		GeneratedAt:    time.Now(),
		Sources:        sourceLabels,
		WindowDays:     opt.days,
		CriticalWeight: opt.critWeight,
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
// local secrets pack; stub is the zero-dependency regex fallback. Both seed
// their confidence threshold from minScore.
func buildAnalyzer(name string, minScore float64) (analyze.Analyzer, error) {
	switch name {
	case "alcatraz", "":
		a := analyze.NewAlcatraz()
		a.SetThreshold(minScore)
		return a, nil
	case "stub":
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

// analyzeSessions runs the detection engine over every message. Matched values
// are captured into SessionInput.Details only when showValues is set; the
// default run aggregates counts and lets the values go.
func analyzeSessions(analyzer analyze.Analyzer, engine *guardrails.Engine, sessions []types.Session, showValues bool) []risk.SessionInput {
	inputs := make([]risk.SessionInput, 0, len(sessions))
	for _, sess := range sessions {
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
		for _, msg := range sess.Messages {
			direction := msg.Role.GuardrailDirection()
			findings, err := analyzer.Analyze(msg.Text)
			if err != nil {
				fmt.Fprintf(os.Stderr, "hooprs: analyzing %s/%s: %v\n", sess.ID, msg.ID, err)
				continue
			}
			for _, f := range findings {
				in.PIISummary[f.EntityType]++
				if direction == "input" {
					in.PIIInput[f.EntityType]++
				} else {
					in.PIIOutput[f.EntityType]++
				}
				if showValues {
					in.Details = append(in.Details, risk.FindingDetail{Entity: f.EntityType, Value: f.Value})
				}
			}
			if !engine.Empty() {
				for _, m := range engine.Match(msg.Text, direction) {
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
		}
		inputs = append(inputs, in)
	}
	return inputs
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
