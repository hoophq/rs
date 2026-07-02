package report

import (
	"os"
	"testing"
	"time"

	"github.com/hoophq/rs/risk"
)

// TestRenderSample writes a sample report to the path in HOOPRS_SAMPLE_OUT.
// It is a dev aid for eyeballing the HTML layout, skipped in normal runs.
func TestRenderSample(t *testing.T) {
	out := os.Getenv("HOOPRS_SAMPLE_OUT")
	if out == "" {
		t.Skip("set HOOPRS_SAMPLE_OUT to render the sample report")
	}
	rep := risk.Report{
		GeneratedAt:   time.Date(2026, 6, 29, 14, 22, 0, 0, time.UTC),
		Sources:       []string{"~/.claude", "~/.cursor", "~/.local/share/opencode"},
		WindowDays:    30,
		SecurityScore: 64,
		Totals: risk.Totals{
			Sessions:         124580,
			Messages:         2984712,
			Findings:         161742,
			HighFindings:     18008,
			EntityTypes:      14,
			CriticalSessions: 1043,
		},
		Tiers: []risk.Tier{
			{Key: "critical", Label: "Critical risk", Note: "high-severity PII detected", Count: 1043, Pct: 1},
			{Key: "minor", Label: "Minor risk", Note: "medium-severity only", Count: 40120, Pct: 32},
			{Key: "low", Label: "Low or none", Note: "no critical or minor PII", Count: 83417, Pct: 67},
		},
		PII: []risk.EntityAgg{
			{Entity: "US_SSN", Family: "Gov ID", Severity: "high", Total: 84, Sessions: 19},
			{Entity: "CREDIT_CARD", Family: "Financial", Severity: "high", Total: 63, Sessions: 15},
			{Entity: "API_KEY", Family: "Secret", Severity: "high", Total: 41, Sessions: 13},
			{Entity: "EMAIL_ADDRESS", Family: "Contact", Severity: "medium", Total: 487, Sessions: 71},
			{Entity: "PHONE_NUMBER", Family: "Contact", Severity: "medium", Total: 256, Sessions: 44},
			{Entity: "IP_ADDRESS", Family: "Network", Severity: "low", Total: 198, Sessions: 52},
			{Entity: "FI_PERSONAL_IDENTITY_CODE", Family: "Government ID", Severity: "high", Total: 120034, Sessions: 8123},
		},
		Sessions: []risk.SessionRow{
			{ID: "sess_9f3a21aaaaaaaaaaaaaa", Tool: "Claude Code", Risk: "critical", Findings: 38, Date: "Jun 27"},
			{ID: "sess_7c0e88", Tool: "Cursor", Risk: "critical", Findings: 31, Date: "Jun 26"},
			{ID: "sess_b412d9", Tool: "Claude Code", Risk: "minor", Findings: 19, Date: "Jun 26"},
			{ID: "sess_4d2a6c", Tool: "Claude Code", Risk: "low", Findings: 3, Date: "Jun 24"},
		},
	}
	f, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := HTML(f, rep, "v0.4.2"); err != nil {
		t.Fatal(err)
	}
}
