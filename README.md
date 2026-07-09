<div align="center">

# 🔍 hooprs

### What did your AI coding agent see?

`hooprs` scans your local AI coding sessions — Claude Code, Cursor, OpenCode —
for PII and secrets, **entirely on your machine**, and shows you exactly
which sessions leaked what.

[![CI](https://github.com/hoophq/rs/actions/workflows/test.yml/badge.svg)](https://github.com/hoophq/rs/actions/workflows/test.yml)
&nbsp;·&nbsp; No gateway &nbsp;·&nbsp; No network &nbsp;·&nbsp; No API calls

<img src="docs/assets/report.png" alt="The hooprs HTML report: security score, sessions by risk tier, PII detection breakdown, and the most exposed sessions" width="720">

</div>

```bash
brew install hoophq/tap/hooprs && hooprs
```

One command. It discovers every session on disk, runs detection in-process,
prints a risk summary to the terminal, and opens a self-contained HTML report
ranking your most exposed sessions.

---

## Why hooprs

Every prompt you type and every file your agent reads becomes session history
on your disk — and some of it is credentials, customer data, national IDs.
You have no idea how much until you look. hooprs looks:

- 🔒 **Local only.** Detection runs in-process on your machine. No DLP
  service, no API calls, nothing leaves your disk — for a scanner that reads
  your secrets, this is the whole point. (The one download is the optional
  NER model when you pass `-ner`, fetched once and cached.)
- ✅ **Verified, not just shape-matched.** Credit cards are Luhn-checked,
  IBANs mod-97-checked, SSNs range-validated. A 16-digit number that fails
  the checksum never reaches your report.
- 🎯 **Ranked, not dumped.** Sessions are tiered `critical` / `minor` / `low`
  and ranked by exposure, so you triage the ten sessions that matter instead
  of scrolling ten thousand findings.
- 🤫 **Value-free reports.** The HTML and JSON reports carry entity types,
  counts, and severities — never the matched values. Sharing the report never
  re-leaks the leak.
- 🚦 **Direction-aware.** Findings split into input (what you typed) and
  output (what the agent pulled into its context) — leaks the agent *read*
  weigh heavier than ones you pasted.

> The command is `hooprs` rather than `rs` because macOS and the BSDs ship a
> stock `rs(1)` utility (reshape a data array) that would otherwise be
> shadowed.

---

## Install

```bash
# Homebrew — macOS & Linux
brew install hoophq/tap/hooprs

# Shell script — macOS & Linux
curl -fsSL https://raw.githubusercontent.com/hoophq/rs/main/install.sh | sh

# npm — also covers Windows (x64)
npx @hoophq/rs
```

All three install a prebuilt binary — no compile step. The shell script
verifies the checksum and installs to `/usr/local/bin` (or `~/.local/bin` when
that's not writable); pin a version with `HOOPRS_VERSION=v0.2.0` or change the
destination with `HOOPRS_INSTALL_DIR=~/bin`. The Homebrew formula lives in
[hoophq/homebrew-tap](https://github.com/hoophq/homebrew-tap); npm pulls the
binary through optional dependencies (`@hoophq/rs-<os>-<arch>`).

Building from source needs Go 1.26+. Everything is pure Go — no cgo: the
[alcatraz](https://github.com/hoophq/alcatraz) detection library plus, for the
optional statistical NER mode, alcatraz's `ner` module and its in-process ONNX
runtime.

```bash
go build -o hooprs ./cmd/hooprs
```

### Faster NER: the ORT build

The prebuilt binaries run the NER model on hugot's pure-Go backend: zero
native dependencies, works everywhere, but CPU-slow — large session histories
can take many minutes. A self-build with the ONNX Runtime backend is roughly
**10x faster** on the same hardware, and can additionally use a GPU
(CoreML/CUDA/DirectML). It needs cgo plus two native libraries:

```bash
# 1. Link-time dependency: libtokenizers.a (match the version in go.mod)
curl -fsSL https://github.com/daulet/tokenizers/releases/download/v1.27.0/libtokenizers.darwin-arm64.tar.gz | tar xz

# 2. Runtime dependency: the ONNX Runtime shared library
brew install onnxruntime   # macOS (auto-detected)
# Linux: download libonnxruntime.so from github.com/microsoft/onnxruntime/releases

# 3. Build with the ORT tag
CGO_LDFLAGS="-L$PWD" go build -tags ORT -o hooprs ./cmd/hooprs

# 4. Select the backend at runtime
HOOPRS_NER_BACKEND=ort ./hooprs -ner
```

The backend is a runtime choice via environment variables, so the same ORT
binary still defaults to the pure-Go backend when the variables are unset:

| Variable | Values | Meaning |
|----------|--------|---------|
| `HOOPRS_NER_BACKEND` | `ort`, `xla` | Inference backend (empty = pure Go) |
| `HOOPRS_NER_ORT_LIB` | path | `libonnxruntime` file or its directory, when not auto-detected |
| `HOOPRS_NER_ACCELERATOR` | `coreml`, `cuda`, `directml` | GPU execution provider (empty = CPU) |

The published releases stay pure-Go on purpose — they cross-compile from one
host and run with zero setup. See alcatraz's
[Faster inference](https://github.com/hoophq/alcatraz#faster-inference-ort-xla-and-gpu)
section for the full build matrix.

## Quickstart

Scan everything, print the summary, write and open `risk-report.html`:

```bash
hooprs
```

Narrow it down:

```bash
# only the last 30 days, plus a machine-readable JSON report
hooprs -days 30 -json risk-report.json

# only Cursor sessions whose project matches a pattern
hooprs -tools cursor -project 'my-app'

# raise the confidence bar (default 0.4)
hooprs -min-score 0.6

# add model-backed PERSON/LOCATION detection (downloads the ONNX model on
# first use; adds significant scan time on large histories)
hooprs -ner

# show the actual leaked values in the terminal (never in the reports)
hooprs -show-values

# same, but masked to the last 4 characters — safe to screen-share
hooprs -mask-values
```

<details>
<summary><b>All flags</b></summary>

<br>

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
| `-min-score` | `0.4` | Minimum detection confidence (0 to 1) to count |
| `-critical-weight` | `60` | Security-score penalty weight (0 to 100) for the critical-session share |
| `-engine` | `alcatraz` | Detection engine: `alcatraz` (full PII set) or `stub` (zero-dependency fallback) |
| `-ner` | `false` | Run the statistical NER model (`PERSON`, `LOCATION`) in-process; downloads the ONNX model on first use and adds significant scan time on large histories |
| `-workers` | `0` | Number of parallel analysis workers; `0` means one per CPU core |
| `-incremental` | `false` | Only scan content appended since the last run |
| `-state` | `~/.risk-analyzer/state.json` | Incremental scan state file |
| `-quiet` | `false` | Suppress the terminal summary |
| `-show-values` | `false` | Print the matched high-severity values for the top 10 critical sessions in the terminal summary (never written to the HTML/JSON reports) |
| `-mask-values` | `false` | Like `-show-values` but each value is masked to its last 4 characters (via the alcatraz anonymizer), so the summary can be shared without re-leaking |
| `-open` | `true` | Open the HTML report in the default browser when done |
| `-version` | `false` | Print the hooprs version and exit |

By default every run is a full snapshot of all your sessions. `-incremental`
persists per-file byte offsets so subsequent runs read only the content
appended since the last run (useful for "what changed since last time").

</details>

---

## Share it

The report's title bar has two buttons, so a scan turns into a message to your
team in one click:

- **Share** rasterizes a 1200×630 summary card (score, risk donut, headline
  counts) to PNG and copies it to your clipboard, then shows the ready-to-paste
  Slack message — paste the image, send the text. If your browser blocks
  clipboard access, the same panel offers a PNG download.
- **Save PDF** opens the print dialog with a print stylesheet that keeps the
  branded dark look and drops the interactive chrome — pick "Save as PDF".

Both run entirely in the page: the card is built from the same value-free data
as the report (entity types and counts, never the matched values), and the
Slack message carries only aggregate counts plus the install one-liner. Sharing
a scan never re-leaks a leak.

---

## What it detects

Structured PII (via the [alcatraz](https://github.com/hoophq/alcatraz) engine)
plus the secret types common in coding sessions (via hooprs's own secrets
pack):

| Family | What's in it |
|--------|--------------|
| **Secrets** | API keys (GitHub, OpenAI, Google, Slack, Stripe, JWT, and a generic high-entropy `key = value` heuristic), AWS access keys, private keys, passwords |
| **Financial** | Credit cards (Luhn-checked), IBAN (mod-97-checked), crypto addresses, ABA routing numbers |
| **Government / national IDs** | US SSN, ITIN, passport, driver license; UK NINO; plus national identifiers for AU, IN, IT, ES, SG, PL, KR, FI and TH |
| **Health** | Medical license; UK NHS and AU Medicare numbers |
| **Contact / network** | Email, phone, IP address, URL |
| **Identity** | Person names and locations, via the in-process NER model (opt-in `-ner`) |

Detection pairs regex **patterns** with checksum and format **validators**
(Luhn, IBAN mod-97, SSN/national-ID range rules), and matches below the
`-min-score` threshold are dropped. Model-backed `PERSON` and `LOCATION`
detection (NER) is opt-in: pass `-ner` to enable it. `-engine stub` selects a
zero-dependency regex fallback.

> **Note on NER:** `PERSON`/`LOCATION` entities need a statistical model, so
> `-ner` loads the
> [alcatraz `ner` module](https://github.com/hoophq/alcatraz#statistical-ner-optional-module)'s
> ONNX model, run **in-process** (pure Go, no cgo). The model is downloaded
> from Hugging Face on first use and cached; inference itself — like all
> detection — runs entirely on your machine. Model inference is CPU-heavy:
> expect noticeably longer scans on large histories with the prebuilt
> binaries. If that matters to you, see
> [Faster NER: the ORT build](#faster-ner-the-ort-build).

---

## How it works

```
sources  →  analyze  →  risk  →  report
claude/      regex +     tiers ·    terminal +
cursor/      validators  score ·    html + json
opencode     (local)     exposure
```

**Sources** discover and parse each tool's on-disk session format into one
normalized model; **analyze** runs the detection engine over every message;
**risk** turns raw findings into tiers, exposure ranking, and a score;
**report** renders the terminal summary and the self-contained HTML.

The risk model:

- **Tier** per session: `critical` (any high-severity entity), `minor`
  (medium-severity only), or `low`.
- **Exposure** ranks sessions by a severity-weighted finding count that favors
  output (data pulled into the agent context) over input.
- **Security Score** = `clamp(0, 100, round(100 − W·critical/total − 20·minor/total))`,
  where `W` is the critical penalty weight (`-critical-weight`, default 60).

Severity and data-family per entity type live in
[`risk/entities.go`](risk/entities.go).

---

## Make it yours

Layer your own detection rules with `-rules <file>` — direction-aware
(`input` = what you typed, `output` = assistant/tool output). See
[`examples/guardrails.json`](examples/guardrails.json):

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

Violations get their own section in the summary and the report, counted per
rule.

---

## Privacy

Everything runs on your machine. The HTML/JSON reports contain **only** entity
types, counts, severities, and session identifiers — never the matched values.
Nothing leaves your machine.

`-show-values` is the one deliberate exception: it prints the matched
high-severity values for the top 10 critical sessions **to the terminal only**,
so you can locate the actual leaks. The HTML and JSON reports stay value-free
even with the flag on — and there's a test pinning that guarantee. Prefer
`-mask-values` when someone else might see your terminal: it prints the same
lines with every value masked to its last 4 characters (alcatraz's anonymizer),
so nothing is re-leaked.

NER (opt-in via `-ner`) performs a single network operation: downloading the
ONNX model from Hugging Face on first use (cached afterwards). Session content
is never uploaded — the model runs in-process, on your machine. The default
run, without `-ner`, performs zero network activity.

---

## Layout

```
cmd/hooprs/    CLI: flags → discover → analyze → risk → render
sources/       discover & parse claude/cursor/opencode sessions
state/         incremental scan offsets
types/         normalized Session/Message model
analyze/       Analyzer interface + alcatraz engine (optional NER), shared secrets pack, Stub fallback
guardrails/    local rules loader + direction-aware matcher
risk/          severity catalog + risk model (tiers, exposure, score)
report/        terminal + self-contained HTML renderer (embedded CSS/JS)
```

---

MIT © [hoop.dev](https://hoop.dev/?utm_source=hooprs&utm_medium=github&utm_campaign=att-launch-072026) — built by the team behind hoop.
