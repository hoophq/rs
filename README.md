# rs — local AI session risk analyzer

`rs` scans your local AI coding sessions (Claude Code, Cursor, OpenCode) for PII
and secrets **entirely on your machine** — no gateway, no network — and produces
a risk summary in the terminal plus a self-contained HTML report you can open or
share.

A built-in analyzer does the detection in-process: regex recognizers backed by
validators (Luhn, IBAN mod-97, SSN range rules). No external DLP service, no API
calls.

```
┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
│   sources    │ → │   analyze    │ → │     risk     │ → │    report    │
│ claude/cursor│   │ regex + rules│   │ tiers/score  │   │ term + html  │
│   /opencode  │   │ (local only) │   │  exposure    │   │   + json     │
└──────────────┘   └──────────────┘   └──────────────┘   └──────────────┘
```

## Build

```bash
go build -o rs ./cmd/rs
```

Zero third-party dependencies; Go 1.24+.

## Usage

Scan everything and write `risk-report.html` in the current directory:

```bash
./rs
```

Common options:

```bash
# scan only the last 30 days, also emit the machine-readable JSON
./rs -days 30 -json risk-report.json

# scan only Cursor sessions whose project matches a pattern
./rs -tools cursor -project 'my-app'

# apply local guardrail rules
./rs -rules examples/guardrails.json

# only count detections at or above a confidence (default 0.4)
./rs -min-score 0.6
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-out` | `risk-report.html` | Path for the self-contained HTML report |
| `-json` | _(off)_ | Also write the machine-readable risk report here |
| `-tools` | `claude,cursor,opencode` | Sources to scan |
| `-project` | _(all)_ | Regexp filter on session project |
| `-session` | _(all)_ | Regexp filter on session id |
| `-days` | `0` (all time) | Only sessions started within the last N days |
| `-home` | `$HOME` | Home directory to discover sessions under |
| `-rules` | _(none)_ | Guardrails rules JSON file |
| `-min-score` | `0.4` | Minimum detection confidence (0–1) to count |
| `-incremental` | `false` | Only scan content appended since the last run |
| `-state` | `~/.risk-analyzer/state.json` | Incremental scan state file |
| `-quiet` | `false` | Suppress the terminal summary |
| `-open` | `true` | Open the HTML report in the default browser when done |

By default every run is a full snapshot of all your sessions. `-incremental`
persists per-file byte offsets so subsequent runs only read newly appended
content (useful for "what changed since last time").

## What it detects

Structured PII and the secret types that matter most for coding sessions:

- **Secrets**: API keys (GitHub, OpenAI, Google, Slack, Stripe, JWT, and a
  generic high-entropy `key = value` heuristic), AWS access keys, private keys,
  passwords.
- **Financial**: credit cards (Luhn-checked), IBAN (mod-97-checked), crypto
  addresses.
- **Identifiers**: US SSN (range-validated), email, phone, IP address, URL.

Detection is **pattern + validator** based. True checksums (Luhn, IBAN) promote
a match to full confidence; format-only checks (SSN range rules) merely gate the
match at its pattern score, so weak signals (e.g. a bare 9-digit number) fall
below the `-min-score` threshold instead of flooding the report.

> **Note on NER:** `PERSON`/`LOCATION`-style entities that require an NLP model
> are intentionally **not** detected in this version. The analyzer is exposed
> behind a small `analyze.Analyzer` interface so a future NLP-backed engine
> can be dropped in without touching the pipeline.

## Risk model

- **Tier** per session: `critical` (any high-severity entity), `minor`
  (medium-severity only), or `low`.
- **Exposure** ranks sessions by a severity-weighted finding count that weights
  output (data pulled into the agent context) over input.
- **Security Score** = `clamp(0, 100, round(100 − 60·critical/total − 20·minor/total))`.

Severity and data-family per entity type live in
[`risk/entities.go`](risk/entities.go).

## Guardrails

Optional local rules, direction-aware (`input` = what you typed, `output` =
assistant/tool output). See [`examples/guardrails.json`](examples/guardrails.json):

```json
{
  "rules": [
    { "name": "internal-hostnames", "type": "regex", "direction": "both",
      "pattern": "\\b[a-z0-9-]+\\.internal\\.example\\.com\\b" },
    { "name": "private-key-material", "type": "deny_words", "direction": "output",
      "words": ["BEGIN RSA PRIVATE KEY"] }
  ]
}
```

## Privacy

Everything runs locally. The HTML/JSON reports contain **only** entity types,
counts, severities, and session identifiers — never the matched values. Nothing
is ever sent anywhere.

## Layout

```
cmd/rs/        CLI: flags → discover → analyze → risk → render
sources/       discover & parse claude/cursor/opencode sessions
state/         incremental scan offsets
types/         normalized Session/Message model
analyze/       Analyzer interface + local regex/secret Stub (+ validators)
guardrails/    local rules loader + direction-aware matcher
risk/          severity catalog + risk model (tiers, exposure, score)
report/        terminal + self-contained HTML renderer (embedded CSS/JS)
```
