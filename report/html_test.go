package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/hoophq/rs/risk"
)

// TestHTMLNeverCarriesValues is the HTML counterpart to
// TestJSONReportNeverCarriesValues: the self-contained report — now including
// the shareable card and the ready-to-paste Slack message — must never embed a
// matched value, even when -show-values collected them for the terminal.
func TestHTMLNeverCarriesValues(t *testing.T) {
	rep := buildWithDetails([]risk.FindingDetail{{Entity: "US_SSN", Value: "078-05-1120"}})

	var buf bytes.Buffer
	if err := HTML(&buf, rep, "v0.4.2"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "078-05-1120") {
		t.Errorf("matched value leaked into the HTML report/share card")
	}
}

// TestHTMLIncludesShareCard pins the share/export affordances: the rasterizable
// SVG card, the Slack message with the install one-liner, and the two buttons.
func TestHTMLIncludesShareCard(t *testing.T) {
	rep := buildWithDetails(nil)

	var buf bytes.Buffer
	if err := HTML(&buf, rep, "v0.4.2"); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	for _, want := range []string{
		`id="rr-sharecard"`,
		`id="rr-share"`,
		`id="rr-pdf"`,
		`id="rr-slacktext"`,
		"brew install hoophq/tap/hooprs",
		"Security Score",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected HTML to contain %q", want)
		}
	}
}
