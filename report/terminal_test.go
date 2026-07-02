package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/hoophq/rs/risk"
)

func buildWithDetails(details []risk.FindingDetail) risk.Report {
	return risk.Build(risk.Meta{GeneratedAt: time.Now()}, []risk.SessionInput{
		{
			Tool: "claude", ID: "sess_critical", Messages: 4,
			PIISummary: map[string]int64{"US_SSN": 2, "EMAIL_ADDRESS": 1},
			PIIOutput:  map[string]int64{"US_SSN": 2, "EMAIL_ADDRESS": 1},
			Details:    details,
		},
		{
			Tool: "cursor", ID: "sess_minor", Messages: 2,
			PIISummary: map[string]int64{"EMAIL_ADDRESS": 3},
			PIIInput:   map[string]int64{"EMAIL_ADDRESS": 3},
		},
	})
}

func TestTerminalShowsValuesForCriticalSessions(t *testing.T) {
	rep := buildWithDetails([]risk.FindingDetail{
		{Entity: "US_SSN", Value: "078-05-1120"},
		{Entity: "US_SSN", Value: "078-05-1120"},
		{Entity: "EMAIL_ADDRESS", Value: "a@example.com"}, // medium severity: filtered out
	})

	var buf bytes.Buffer
	Terminal(&buf, rep)
	out := buf.String()

	if !strings.Contains(out, "Matched values") {
		t.Fatalf("expected a matched-values section, got:\n%s", out)
	}
	if !strings.Contains(out, "078-05-1120") {
		t.Errorf("expected the SSN value in the output, got:\n%s", out)
	}
	if !strings.Contains(out, "×2") {
		t.Errorf("expected the duplicate value collapsed with a ×2 count, got:\n%s", out)
	}
	if strings.Contains(out, "a@example.com") {
		t.Errorf("medium-severity value must not be printed, got:\n%s", out)
	}
}

func TestTerminalOmitsValuesSectionByDefault(t *testing.T) {
	rep := buildWithDetails(nil) // no -show-values: no details collected

	var buf bytes.Buffer
	Terminal(&buf, rep)
	if strings.Contains(buf.String(), "Matched values") {
		t.Errorf("matched-values section must not appear without details:\n%s", buf.String())
	}
}

func TestJSONReportNeverCarriesValues(t *testing.T) {
	rep := buildWithDetails([]risk.FindingDetail{{Entity: "US_SSN", Value: "078-05-1120"}})

	data, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "078-05-1120") {
		t.Errorf("matched value leaked into the JSON report: %s", data)
	}
}
