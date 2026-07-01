# hooprs

Local PII and secrets risk scanner for AI coding sessions (Claude Code, Cursor,
OpenCode). It runs on your machine. No gateway, no network.

```bash
npx @hoophq/rs                # scan, then open the HTML risk report
npm i -g @hoophq/rs && hooprs # or install hooprs as a global command
```

The command is named `hooprs` (not `rs`) so it never collides with the BSD
`rs(1)` utility that ships with macOS.

npm installs the matching prebuilt binary through platform-specific optional
dependencies (`@hoophq/rs-<os>-<arch>`).

Read the [project README](https://github.com/hoophq/rs#readme) for the flags,
risk model, guardrails, and privacy.
