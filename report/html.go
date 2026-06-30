// Package report renders a risk.Report as a self-contained HTML document and as
// a terminal summary. The HTML embeds its own CSS and a little vanilla JS, so
// the generated file is a single shareable artifact with no external assets.
package report

import (
	"embed"
	"fmt"
	"html/template"
	"io"
	"math"
	"strconv"
	"strings"

	"github.com/hoophq/rs/risk"
)

//go:embed assets/report.css assets/report.html.tmpl
var assets embed.FS

// circleC is the circumference of the donut ring (r=80), matching the prototype.
const circleC = 2 * math.Pi * 80

var tierColors = map[string]string{
	"critical": "#e5484d",
	"minor":    "#e6a23c",
	"low":      "#4fb477",
}

type donutSeg struct {
	Key, Color, Dash, Offset string
}

type tierView struct {
	Key, Label, Note, Color, CountLabel string
	Pct                                 int
}

type filterView struct {
	Key, Label string
	Count      int
	Active     bool
}

type piiView struct {
	Entity, Family, Severity, TotalLabel, SessionsLabel string
	BarPct                                              int
}

type sessView struct {
	ID, Tool, Risk, FindingsLabel, Date string
}

type htmlView struct {
	CSS            template.CSS
	Version        string
	GeneratedLabel string
	SourcesLabel   string
	ScopeLabel     string
	WindowLabel    string
	Score          int
	Donut          []donutSeg
	SessionsLabel  string
	Tiers          []tierView
	KpiSessions    string
	KpiSessionsSub string
	KpiCritical    string
	KpiCriticalSub string
	KpiFindings    string
	KpiFindingsSub string
	PIISub         string
	Filters        []filterView
	PII            []piiView
	Sessions       []sessView
}

// HTML renders the report as a standalone HTML document.
func HTML(w io.Writer, rep risk.Report, version string) error {
	cssBytes, err := assets.ReadFile("assets/report.css")
	if err != nil {
		return err
	}
	tmplBytes, err := assets.ReadFile("assets/report.html.tmpl")
	if err != nil {
		return err
	}
	tmpl, err := template.New("report").Parse(string(tmplBytes))
	if err != nil {
		return err
	}
	return tmpl.Execute(w, buildView(rep, version, template.CSS(cssBytes)))
}

func buildView(rep risk.Report, version string, css template.CSS) htmlView {
	total := float64(rep.Totals.Sessions)

	var donut []donutSeg
	var tiers []tierView
	acc := 0.0
	critPct := 0
	for _, t := range rep.Tiers {
		dash := fmt.Sprintf("0 %.2f", circleC)
		offset := 0.0
		if total > 0 {
			seg := (float64(t.Count)/total)*circleC - 7
			if seg < 0 {
				seg = 0
			}
			dash = fmt.Sprintf("%.2f %.2f", seg, circleC-seg)
			offset = -(acc / total) * circleC
		}
		donut = append(donut, donutSeg{
			Key:    t.Key,
			Color:  tierColors[t.Key],
			Dash:   dash,
			Offset: fmt.Sprintf("%.2f", offset),
		})
		tiers = append(tiers, tierView{
			Key:        t.Key,
			Label:      t.Label,
			Note:       t.Note,
			Color:      tierColors[t.Key],
			CountLabel: comma(int64(t.Count)),
			Pct:        t.Pct,
		})
		if t.Key == "critical" {
			critPct = t.Pct
		}
		acc += float64(t.Count)
	}

	counts := map[string]int{"high": 0, "medium": 0, "low": 0}
	var maxTotal int64 = 1
	for _, e := range rep.PII {
		counts[e.Severity]++
		if e.Total > maxTotal {
			maxTotal = e.Total
		}
	}
	filters := []filterView{
		{Key: "all", Label: "All", Count: len(rep.PII), Active: true},
		{Key: "high", Label: "High", Count: counts["high"]},
		{Key: "medium", Label: "Medium", Count: counts["medium"]},
		{Key: "low", Label: "Low", Count: counts["low"]},
	}

	var pii []piiView
	for _, e := range rep.PII {
		pii = append(pii, piiView{
			Entity:        e.Entity,
			Family:        e.Family,
			Severity:      e.Severity,
			TotalLabel:    comma(e.Total),
			SessionsLabel: comma(int64(e.Sessions)),
			BarPct:        int(math.Round(float64(e.Total) / float64(maxTotal) * 100)),
		})
	}

	var sessions []sessView
	for _, s := range rep.Sessions {
		sessions = append(sessions, sessView{
			ID:            shortID(s.ID),
			Tool:          s.Tool,
			Risk:          s.Risk,
			FindingsLabel: comma(s.Findings),
			Date:          s.Date,
		})
	}

	return htmlView{
		CSS:            css,
		Version:        version,
		GeneratedLabel: rep.GeneratedAt.Format("Jan 2, 2006 15:04"),
		SourcesLabel:   strings.Join(rep.Sources, ", "),
		ScopeLabel:     fmt.Sprintf("%s sessions · %s messages", comma(int64(rep.Totals.Sessions)), comma(int64(rep.Totals.Messages))),
		WindowLabel:    windowLabel(rep.WindowDays),
		Score:          rep.SecurityScore,
		Donut:          donut,
		SessionsLabel:  comma(int64(rep.Totals.Sessions)),
		Tiers:          tiers,
		KpiSessions:    comma(int64(rep.Totals.Sessions)),
		KpiSessionsSub: comma(int64(rep.Totals.Messages)) + " messages analyzed",
		KpiCritical:    comma(int64(rep.Totals.CriticalSessions)),
		KpiCriticalSub: fmt.Sprintf("%d%% of all sessions", critPct),
		KpiFindings:    comma(rep.Totals.Findings),
		KpiFindingsSub: fmt.Sprintf("%s high severity · %d entity types", comma(rep.Totals.HighFindings), rep.Totals.EntityTypes),
		PIISub:         fmt.Sprintf("%s findings · %d entity types · %s high severity", comma(rep.Totals.Findings), rep.Totals.EntityTypes, comma(rep.Totals.HighFindings)),
		Filters:        filters,
		PII:            pii,
		Sessions:       sessions,
	}
}

func windowLabel(days int) string {
	if days <= 0 {
		return "all-time"
	}
	return fmt.Sprintf("%d-day window", days)
}

func shortID(id string) string {
	if len(id) <= 16 {
		return id
	}
	return id[:14] + "…"
}

// comma formats an integer with thousands separators.
func comma(n int64) string {
	s := strconv.FormatInt(n, 10)
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	var out []byte
	for i := 0; i < len(s); i++ {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, s[i])
	}
	if neg {
		return "-" + string(out)
	}
	return string(out)
}
