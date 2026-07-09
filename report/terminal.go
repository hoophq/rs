package report

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/hoophq/rs/risk"
)

// Terminal writes a concise human-readable risk summary to w.
func Terminal(w io.Writer, rep risk.Report) {
	p := func(format string, a ...any) { fmt.Fprintf(w, format, a...) }

	p("\nRisk Analysis Report\n")
	p("Security Score: %d/100\n", rep.SecurityScore)
	sources := strings.Join(rep.Sources, ", ")
	if sources == "" {
		sources = "no sources"
	}
	p("%s · %s · %s sessions · %s messages\n",
		sources, windowLabel(rep.WindowDays),
		comma(int64(rep.Totals.Sessions)), comma(int64(rep.Totals.Messages)))

	p("\nRisk tiers:\n")
	for _, t := range rep.Tiers {
		p("  %-13s %6s sessions  %3d%%\n", t.Label, comma(int64(t.Count)), t.Pct)
	}

	p("\nFindings: %s total · %s high severity · %d entity types · %s critical sessions\n",
		comma(rep.Totals.Findings), comma(rep.Totals.HighFindings),
		rep.Totals.EntityTypes, comma(int64(rep.Totals.CriticalSessions)))
	p("Direction: %s in input · %s in output\n", comma(rep.Totals.Input), comma(rep.Totals.Output))

	if len(rep.PII) > 0 {
		p("\nPII & secrets:\n")
		tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "  ENTITY\tFAMILY\tSEVERITY\tTOTAL\tSESSIONS")
		for _, e := range rep.PII {
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\n",
				e.Entity, e.Family, e.Severity, comma(e.Total), comma(int64(e.Sessions)))
		}
		tw.Flush()
	}

	if len(rep.Sessions) > 0 {
		const limit = 10
		n := len(rep.Sessions)
		if n > limit {
			n = limit
		}
		p("\nMost exposed sessions:\n")
		tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "  RISK\tSESSION\tTOOL\tFINDINGS\tDATE")
		for _, s := range rep.Sessions[:n] {
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\n",
				s.Risk, shortID(s.ID), s.Tool, comma(s.Findings), s.Date)
		}
		tw.Flush()
		if len(rep.Sessions) > limit {
			p("  … and %s more (see the HTML report)\n", comma(int64(len(rep.Sessions)-limit)))
		}
	}

	printValues(w, rep.Sessions, rep.ValuesMasked)

	if len(rep.Guardrails) > 0 {
		p("\nGuardrail violations: %s\n", comma(int64(len(rep.Guardrails))))
		byRule := map[string]int{}
		for _, v := range rep.Guardrails {
			byRule[v.RuleName]++
		}
		rules := make([]string, 0, len(byRule))
		for rule := range byRule {
			rules = append(rules, rule)
		}
		sort.Strings(rules)
		tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		for _, rule := range rules {
			fmt.Fprintf(tw, "  %s\t%s hits\n", rule, comma(int64(byRule[rule])))
		}
		tw.Flush()
	}
	p("\n")
}

// maxValuesPerSession caps the distinct values printed per session so one
// pathological session cannot flood the terminal.
const maxValuesPerSession = 20

// printValues renders the matched high-severity values that risk.Build kept on
// the top critical sessions (populated only with -show-values or
// -mask-values). Repeated values collapse into one line with an occurrence
// count. masked flips the caption: masked values are already anonymized, raw
// ones warrant the sensitivity warning.
func printValues(w io.Writer, sessions []risk.SessionRow, masked bool) {
	any := false
	for _, s := range sessions {
		if len(s.Values) > 0 {
			any = true
			break
		}
	}
	if !any {
		return
	}

	fmt.Fprintf(w, "\nMatched values (top %d critical sessions, high severity only):\n", risk.MaxValueSessions)
	if masked {
		fmt.Fprintf(w, "  Values are masked to their last 4 characters. Not written to the HTML/JSON reports.\n")
	} else {
		fmt.Fprintf(w, "  Sensitive output: these are the detected values themselves. Not written to the HTML/JSON reports.\n")
	}
	for _, s := range sessions {
		if len(s.Values) == 0 {
			continue
		}
		fmt.Fprintf(w, "\n  %s · %s\n", shortID(s.ID), s.Tool)
		tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		printed := 0
		skipped := 0
		for _, v := range dedupeValues(s.Values) {
			if printed >= maxValuesPerSession {
				skipped++
				continue
			}
			line := fmt.Sprintf("    %s\t%s", v.Entity, v.Value)
			if v.Count > 1 {
				line += fmt.Sprintf("\t×%s", comma(int64(v.Count)))
			}
			fmt.Fprintln(tw, line)
			printed++
		}
		tw.Flush()
		if skipped > 0 {
			fmt.Fprintf(w, "    … and %s more distinct values\n", comma(int64(skipped)))
		}
	}
}

// valueLine is one deduplicated matched value with its occurrence count.
type valueLine struct {
	Entity string
	Value  string
	Count  int
}

// dedupeValues collapses identical (entity, value) pairs, preserving first-seen
// order so the output follows the order findings appeared in the session.
func dedupeValues(details []risk.FindingDetail) []valueLine {
	index := map[risk.FindingDetail]int{}
	lines := make([]valueLine, 0, len(details))
	for _, d := range details {
		if i, ok := index[d]; ok {
			lines[i].Count++
			continue
		}
		index[d] = len(lines)
		lines = append(lines, valueLine{Entity: d.Entity, Value: d.Value, Count: 1})
	}
	return lines
}
