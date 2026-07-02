package risk

import (
	"math"
	"sort"
	"time"
)

// Exposure magnitude weights output (data returned into the agent context)
// over input (what the engineer typed), matching the dashboard adapter.
const (
	outputWeight = 0.78
	inputWeight  = 1 - outputWeight
)

// Violation is one guardrail rule match with its session context.
type Violation struct {
	Tool         string   `json:"tool"`
	SessionID    string   `json:"session_id"`
	MessageID    string   `json:"message_id"`
	RuleName     string   `json:"rule_name"`
	RuleType     string   `json:"rule_type"`
	Direction    string   `json:"direction"`
	MatchedWords []string `json:"matched_words,omitempty"`
}

// SessionInput is the aggregated detection result for one session, produced by
// the orchestration layer before the risk model runs.
type SessionInput struct {
	Tool       string
	ID         string
	Project    string
	StartedAt  time.Time
	Messages   int
	PIISummary map[string]int64 // entity -> count (all directions)
	PIIInput   map[string]int64
	PIIOutput  map[string]int64
	Guardrails []Violation
	// Details carries the matched values. The orchestration layer populates it
	// only when the user opts in (-show-values); it stays nil otherwise.
	Details []FindingDetail
}

// FindingDetail is one matched value, captured only on explicit opt-in.
type FindingDetail struct {
	Entity string
	Value  string
}

// Meta is the run-level context shown in the report header.
type Meta struct {
	GeneratedAt time.Time
	Sources     []string
	WindowDays  int
}

// Tier is one risk bucket with its session count and share.
type Tier struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Note  string `json:"note"`
	Count int    `json:"count"`
	Pct   int    `json:"pct"`
}

// EntityAgg is the cross-session aggregate for one entity type.
type EntityAgg struct {
	Entity   string `json:"entity"`
	Family   string `json:"family"`
	Severity string `json:"severity"`
	Total    int64  `json:"total"`
	Sessions int    `json:"sessions"`
}

// SessionRow is one row of the "most exposed sessions" feed.
type SessionRow struct {
	ID       string `json:"id"`
	Tool     string `json:"tool"`
	Risk     string `json:"risk"`
	Findings int64  `json:"findings"`
	Date     string `json:"date"`

	// Values are the high-severity matched values behind a critical session,
	// present only with -show-values and only on the top critical rows. The
	// json:"-" tag is a hard guarantee: matched values never reach the
	// machine-readable report, only the terminal summary.
	Values []FindingDetail `json:"-"`

	exposure float64
}

// MaxValueSessions caps how many critical sessions keep their matched values:
// the ten most exposed ones, mirroring the terminal's session-feed limit.
const MaxValueSessions = 10

// Totals are the headline counters.
type Totals struct {
	Sessions         int   `json:"sessions"`
	Messages         int   `json:"messages"`
	Findings         int64 `json:"findings"`
	HighFindings     int64 `json:"high_findings"`
	EntityTypes      int   `json:"entity_types"`
	CriticalSessions int   `json:"critical_sessions"`
	Input            int64 `json:"input"`
	Output           int64 `json:"output"`
	Guardrails       int   `json:"guardrails"`
}

// Report is the full risk summary consumed by the renderers.
type Report struct {
	GeneratedAt   time.Time    `json:"generated_at"`
	Sources       []string     `json:"sources"`
	WindowDays    int          `json:"window_days"`
	SecurityScore int          `json:"security_score"`
	Totals        Totals       `json:"totals"`
	Tiers         []Tier       `json:"risk_tiers"`
	PII           []EntityAgg  `json:"pii"`
	Sessions      []SessionRow `json:"sessions"`
	Guardrails    []Violation  `json:"guardrails"`
}

// Build computes the risk summary from the per-session aggregates.
func Build(meta Meta, sessions []SessionInput) Report {
	tierCount := map[string]int{"critical": 0, "minor": 0, "low": 0}
	rows := make([]SessionRow, 0, len(sessions))
	aggByEntity := map[string]*EntityAgg{}
	sessionsByEntity := map[string]map[string]bool{}

	var totalMessages int
	var totalFindings, highFindings, totalInput, totalOutput int64
	violations := []Violation{}

	for _, s := range sessions {
		tier := sessionTier(s.PIISummary)
		tierCount[tier]++

		var findingTotal int64
		for entity, count := range s.PIISummary {
			findingTotal += count
			totalFindings += count
			info := Info(entity)
			if info.Severity == SeverityHigh {
				highFindings += count
			}
			agg := aggByEntity[entity]
			if agg == nil {
				agg = &EntityAgg{Entity: entity, Family: info.Family, Severity: string(info.Severity)}
				aggByEntity[entity] = agg
				sessionsByEntity[entity] = map[string]bool{}
			}
			agg.Total += count
			sessionsByEntity[entity][s.Tool+"/"+s.ID] = true
		}
		for _, count := range s.PIIInput {
			totalInput += count
		}
		for _, count := range s.PIIOutput {
			totalOutput += count
		}
		totalMessages += s.Messages
		violations = append(violations, s.Guardrails...)

		rows = append(rows, SessionRow{
			ID:       s.ID,
			Tool:     displayTool(s.Tool),
			Risk:     tier,
			Findings: findingTotal,
			Date:     dateLabel(s.StartedAt),
			Values:   highSeverityValues(s.Details),
			exposure: directedExposure(s.PIIOutput, outputWeight) + directedExposure(s.PIIInput, inputWeight),
		})
	}

	pii := make([]EntityAgg, 0, len(aggByEntity))
	for entity, agg := range aggByEntity {
		agg.Sessions = len(sessionsByEntity[entity])
		pii = append(pii, *agg)
	}
	sort.Slice(pii, func(i, j int) bool {
		ri, rj := severityRank[Severity(pii[i].Severity)], severityRank[Severity(pii[j].Severity)]
		if ri != rj {
			return ri < rj
		}
		return pii[i].Total > pii[j].Total
	})

	// critical sessions first, then by exposure magnitude within each tier
	tierOrder := map[string]int{"critical": 0, "minor": 1, "low": 2}
	sort.SliceStable(rows, func(i, j int) bool {
		if tierOrder[rows[i].Risk] != tierOrder[rows[j].Risk] {
			return tierOrder[rows[i].Risk] < tierOrder[rows[j].Risk]
		}
		return rows[i].exposure > rows[j].exposure
	})

	// Matched values stay only on the ten most exposed critical sessions
	// (critical rows sort first, so they lead the slice); every other row is
	// counts-only.
	valueRows := 0
	for i := range rows {
		if rows[i].Risk == "critical" && valueRows < MaxValueSessions {
			valueRows++
			continue
		}
		rows[i].Values = nil
	}

	total := len(sessions)
	pct := func(n int) int {
		if total == 0 {
			return 0
		}
		return int(math.Round(float64(n) / float64(total) * 100))
	}

	tiers := []Tier{
		{Key: "critical", Label: "Critical risk", Note: "high-severity PII detected", Count: tierCount["critical"], Pct: pct(tierCount["critical"])},
		{Key: "minor", Label: "Minor risk", Note: "medium-severity only", Count: tierCount["minor"], Pct: pct(tierCount["minor"])},
		{Key: "low", Label: "Low or none", Note: "no critical or minor PII", Count: tierCount["low"], Pct: pct(tierCount["low"])},
	}

	return Report{
		GeneratedAt:   meta.GeneratedAt,
		Sources:       meta.Sources,
		WindowDays:    meta.WindowDays,
		SecurityScore: securityScore(total, tierCount["critical"], tierCount["minor"]),
		Totals: Totals{
			Sessions:         total,
			Messages:         totalMessages,
			Findings:         totalFindings,
			HighFindings:     highFindings,
			EntityTypes:      len(aggByEntity),
			CriticalSessions: tierCount["critical"],
			Input:            totalInput,
			Output:           totalOutput,
			Guardrails:       len(violations),
		},
		Tiers:      tiers,
		PII:        pii,
		Sessions:   rows,
		Guardrails: violations,
	}
}

// sessionTier classifies a session: critical if it carries any high-severity
// entity, minor if it carries only medium-severity entities, else low.
func sessionTier(summary map[string]int64) string {
	tier := "low"
	for entity := range summary {
		switch Info(entity).Severity {
		case SeverityHigh:
			return "critical"
		case SeverityMedium:
			tier = "minor"
		}
	}
	return tier
}

// highSeverityValues keeps only the high-severity details — the findings that
// made the session critical — dropping the medium/low noise around them.
func highSeverityValues(details []FindingDetail) []FindingDetail {
	var kept []FindingDetail
	for _, d := range details {
		if Info(d.Entity).Severity == SeverityHigh {
			kept = append(kept, d)
		}
	}
	return kept
}

func directedExposure(summary map[string]int64, weight float64) float64 {
	var score float64
	for entity, count := range summary {
		score += float64(count) * severityWeight[Info(entity).Severity] * weight
	}
	return score
}

// securityScore is a tier-weighted penalty out of 100.
func securityScore(total, critical, minor int) int {
	if total == 0 {
		return 100
	}
	penalty := 60*float64(critical)/float64(total) + 20*float64(minor)/float64(total)
	score := int(math.Round(100 - penalty))
	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	return score
}

func displayTool(tool string) string {
	switch tool {
	case "claude":
		return "Claude Code"
	case "cursor":
		return "Cursor"
	case "opencode":
		return "OpenCode"
	default:
		return tool
	}
}

func dateLabel(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.Format("Jan 2")
}
