# Changelog

All notable changes to AI Tripwire. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow SemVer.

## [Unreleased]

### Security corrections

- Register WebFetch before execution, refresh owned registrations on upgrades, and validate effective event/matcher coverage.
- Canonicalize protected paths and symlink targets; cover redirects, baseline Git directory options and additional secret readers.
- Limit self-email, Git and temporary-delete exceptions to understood operations. Check every effective push URL against a canonical host/path; do not inherit an exception across shell commands.
- Gate absolute/attached upload forms, remote rsync targets and GitHub API mutations.
- Bound post-tool signature work, fix nested-markdown matching, fence rule/memory reads and persist every alarm without trusting writable deduplication state.
- Report disabled/malformed hook settings as failures; include rules, policy and ignored new instruction content in integrity reporting.
- Make transcript patterns portable, keep auditing after malformed config, and create private, unique scanner output.
- Never stage or commit a baseline during installation or upgrades. Human review is required before accepting existing memory.
- Add isolated regressions for both editions, Linux/macOS CI, and tests keeping executable protocol examples in sync.

### Limits

Hooks remain a defense-in-depth layer, not an OS sandbox. The post-tool fence is advisory. A general, securely enrolled recurring-workflow registry is not part of this patch; repeated approvals and memory content never create grants automatically.

## [1.1.0] — 2026-09-05

First public release. Before publishing, the kit went through five independent adversarial reviews
(prompt-injection researcher, detection engineer, open-source maintainer, enterprise CISO, red-teamer);
everything they rated blocking is fixed here, with a test per finding.

### Fixed — outbound gate (`guard-irreversible.py`)
- A benign clause could short-circuit the whole decision (`gws gmail +send --to me ; aws s3 cp …` was allowed).
  Every gate now evaluates the whole command; the decision is made once, at the end (deny > ask > allow).
- Network requests that carry local data were not gated unless they used `-d ` with a space: `curl -d@.env`,
  `curl "…?x=$(cat file)"`, `curl … < .env`, shell variables in URLs, `python -c`/`node -e` socket one-liners,
  and DNS queries built from local data now ask.
- Self-modification through the shell was not gated (`mv`/`tee`/`ln`/`sed -i`/`python -c` onto hooks or
  settings, `cd ~/.claude && cat > hooks/x`). Any write-capable command or redirect aimed at a protected
  path now asks; deleting the hooks is denied.
- `/bin/nc` evaded the netcat deny (anchor bug).
- MCP tools named with hyphens or `create_*`/`update_*`/`post*` verbs (`notion-create-pages`,
  `chat_postMessage`, `create_event`, `create_pull_request`) and the built-in `Artifact` publisher now ask.
- Secret-read gate extended to `xxd`, `od`, `strings`, `dd if=`, `$(<file)`, `.key`, `.git-credentials`.

### Fixed — evidence trail (detection review)
- The alarm log, the `~/.claude` baseline repository, `tripwire.json` and `~/.claude.json` are now protected paths
  for shell writes; write operations of `git` on the baseline (`commit`, `--amend`, `reset`, `reflog`, …) ask —
  an agent could previously append "always approve" to a memory file and re-commit a "clean" baseline silently.
- Alarms are mirrored to the OS unified log (`logger -t tripwire`), carry provenance (session, cwd, URL/query/file),
  and are de-duplicated within a minute; the baseline now tracks the alarm log itself.
- New gates from the red-team review: `curl … | sh` (download piped into an interpreter), running a file written in
  the last 15 minutes (two-step indirection), network commands written into a script, `WebFetch` URLs carrying data
  or pointing at webhook/tunnel hosts, MCP tools named push/navigate/refund/charge/payout, today's tunnel and paste
  domains (`ngrok-free.app`, `trycloudflare.com`, `0x0.st`, `file.io`, …).

### Fixed — fence (`guard-untrusted-data.py`)
- The "AI-directed imperative" signature fired on ordinary news headlines ("AI firms open new labs") and
  flooded the alarm log; it now requires an instruction addressed to the assistant ("you must run…",
  "Assistant: send…").
- Invisible-character detection missed U+200D (the character used in the Rules File Backdoor case) after it
  had been removed to avoid emoji false positives; it now flags U+200D outside emoji sequences, plus U+00AD
  and the Unicode Tags block (ASCII smuggling).
- Files read from disk that typically carry third-party instructions (README, CLAUDE.md, rules files,
  dependencies) are now fenced too.

### Fixed — scanner and integrity report
- Same invisible-character logic as the fence; `.vscode/settings.json` and `.vscode/mcp.json` added to the
  inventory; token-like MCP arguments are masked in the report; the report is marked confidential.
- Scanner: `set -u` plus an unset `$APPDATA` silently aborted part of the inventory on macOS/Linux (fixed); signatures
  now match across line breaks and after NFKC normalization; wider inventory (Cursor/Windsurf/Copilot/Gemini
  configs, `.git/hooks`, VS Code Copilot/MCP settings), config audit prints `disableAllHooks`, `apiKeyHelper`, `env`,
  `statusLine`; shell-rc check covers `ANTHROPIC_BASE_URL`/`NODE_OPTIONS`/`LD_PRELOAD`; default depth 12 with a notice.
- Integrity report also audits `settings.local.json`, checks `disableAllHooks` and that the guard's matcher really
  covers Bash; the fail-closed self-test now checks for an actual ask/deny decision, not just any output.

### Changed — installer and configuration
- Configuration moved from a block inside the hook to `~/.claude/tripwire.json`, written once and never
  overwritten on upgrade.
- `install.sh` refuses to create the baseline when `~/.claude` sits inside another git repository or already
  has a remote (it would otherwise have committed hooks and settings into e.g. a dotfiles repo); robust to
  malformed `settings.json`; tested twice in a row in CI.
- `tripwire-run.sh` wrapper resolves `python3`/`python` and emits the fail-closed decision itself if neither
  exists (a hook that cannot start would otherwise fail open at the harness level).

### Changed — repository
- Claude review workflow runs only on same-repository, human PRs; the review agent gets the kit's own fence
  and no write tools; `@claude` responds only to maintainers.
- CODEOWNERS, issue-template routing (bypasses → private reporting), this changelog.
- Documents: per-case primary-source links, clean read-only Phase 2 session recipe, explicit limits
  (static GET, DNS, Read coverage, harness timeout, Claude-Code-only hooks), managed-device and
  breach-notification cautions.

### Credits
The five pre-publication reviews were performed by Claude agents acting as adversarial reviewers, orchestrated
by the maintainer. Human reviewers who report bypasses are credited here — see [SECURITY.md](SECURITY.md).

## [1.0.0] — 2026-09-04

Initial private version: the two hooks, the scanner, the integrity report, the protocol document (EN + PT-BR),
64 behaviour tests, CI.
