# rs

Local PII and secrets risk scanner for AI coding sessions (Claude Code, Cursor,
OpenCode). It runs on your machine. No gateway, no network.

```bash
npx @hoophq/rs            # scan, then open the HTML risk report
npm i -g @hoophq/rs && rs # or install rs as a global command
```

npm installs the matching prebuilt binary through platform-specific optional
dependencies (`@hoophq/rs-<os>-<arch>`).

Read the [project README](https://github.com/hoophq/rs#readme) for the flags,
risk model, guardrails, and privacy.
