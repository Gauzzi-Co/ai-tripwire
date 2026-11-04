#!/usr/bin/env bash
# integrity-report.sh — AI Tripwire · weekly integrity report · client edition v1.0
# Verifies the defenses exist, are registered and fail closed; shows what changed in
# memories/instructions since the last baseline (git in ~/.claude) and searches for
# injection signatures in NEW content only. Exit 1 on any CRITICAL problem.
# Prerequisite: ~/.claude versioned with git (see the document, Tripwire › step 3).
set -uo pipefail
CLAUDE_DIR="$HOME/.claude"; FAIL=0
DEFENSES=(.gitignore settings.json settings.local.json tripwire.json hooks/ agents/ commands/ skills/ plugins/ rules/ memory/ CLAUDE.md CLAUDE.local.md ':(glob)projects/*/memory/**')
INSTRUCTIONS=(rules/ memory/ agents/ commands/ skills/ CLAUDE.md CLAUDE.local.md ':(glob)projects/*/memory/**')
echo "== TRIPWIRE INTEGRITY REPORT — $(date '+%Y-%m-%d %H:%M %Z') =="

echo; echo "-- claude binary (an alias/function in front of the binary = vector) --"
type claude 2>&1 | head -2

echo; echo "-- Defense changelog (git, last 10 changes) --"
TOP="$(git -C "$CLAUDE_DIR" rev-parse --show-toplevel 2>/dev/null || true)"
if [ "$TOP" = "$(cd "$CLAUDE_DIR" 2>/dev/null && pwd -P)" ] && git -C "$CLAUDE_DIR" rev-parse --verify HEAD >/dev/null 2>&1; then
  if ! git -C "$CLAUDE_DIR" log --oneline -10; then echo "CRITICAL: cannot inspect baseline log"; FAIL=1; fi
  echo; echo "-- UNCOMMITTED changes on the defense surface --"
  if ! CH="$(git -C "$CLAUDE_DIR" status --porcelain --ignored -uall -- "${DEFENSES[@]}" 2>/dev/null)"; then echo "CRITICAL: cannot inspect defense status"; FAIL=1; fi
  if [ -n "$CH" ]; then echo "$CH"; echo "^ defenses changed without a commit — if you did not do this, INVESTIGATE before committing."; else echo "clean."; fi
else
  echo "CRITICAL: ~/.claude is not a git repository — no baseline, no tamper detection."; FAIL=1
fi

echo; echo "-- Hook files present --"
for f in guard-irreversible.py guard-untrusted-data.py tripwire-run.sh; do
  if [ -f "$CLAUDE_DIR/hooks/$f" ]; then echo "  OK    $f"; else echo "  CRITICAL: MISSING $f"; FAIL=1; fi
done
echo; echo "-- Hooks registered in settings.json --"
for f in guard-irreversible.py guard-untrusted-data.py; do
  if grep -q "$f" "$CLAUDE_DIR/settings.json" 2>/dev/null; then echo "  OK    $f"; else echo "  CRITICAL: NOT REGISTERED $f"; FAIL=1; fi
done
echo; echo "-- Fail-closed self-test (garbage input must produce a LOUD response) --"
for f in guard-irreversible.py guard-untrusted-data.py; do
  out="$(echo 'not json {{{' | python3 "$CLAUDE_DIR/hooks/$f" 2>/dev/null || true)"
  if printf '%s' "$out" | grep -qE '"permissionDecision": *"(ask|deny)"|additionalContext'; then echo "  OK    $f (loud on error)"; else echo "  CRITICAL: $f SILENT or permissive on error"; FAIL=1; fi
done

echo; echo "-- Dangerous permissions in settings --"
for SF in "$CLAUDE_DIR/settings.json" "$CLAUDE_DIR/settings.local.json"; do [ -f "$SF" ] || continue; echo "  ($SF)"
if ! python3 - "$SF" <<'PYEOF'
import json, sys, re, os
failed = False
def critical(message):
    global failed
    print("  CRITICAL: " + message)
    failed = True
try:
    with open(sys.argv[1], encoding="utf-8") as f:
        d = json.load(f)
    if not isinstance(d, dict):
        raise ValueError("settings must be an object")
    p = d.get("permissions", {})
    if not isinstance(p, dict):
        raise ValueError("permissions must be an object")
    if p.get("defaultMode") == "bypassPermissions":
        critical("defaultMode = bypassPermissions")
    rules = p.get("allow", [])
    if not isinstance(rules, list):
        raise ValueError("permissions.allow must be a list")
    bad = [r for r in rules if re.search(r"^Bash$|Bash\(\*?\)|curl|wget|scp|rclone|\brm\b", str(r))]
    print("  broad allow rules:", bad or "none")
    if d.get("disableAllHooks"):
        critical("disableAllHooks is set")
    if os.path.basename(sys.argv[1]) == "settings.json" or "hooks" in d:
        hooks = d.get("hooks", {})
        if not isinstance(hooks, dict):
            raise ValueError("hooks must be an object")
        requirements = {
            "PreToolUse": ("guard-irreversible.py", ["Bash", "Write", "Edit", "MultiEdit", "NotebookEdit", "WebFetch", "Artifact", "mcp__test__send"]),
            "PostToolUse": ("guard-untrusted-data.py", ["Bash", "Read", "WebFetch", "WebSearch", "mcp__test__read"]),
        }
        for event, (script, tools) in requirements.items():
            entries = hooks.get(event, [])
            if not isinstance(entries, list):
                raise ValueError("hook event must be a list")
            covered = set()
            for entry in entries:
                if not isinstance(entry, dict) or not isinstance(entry.get("hooks"), list):
                    raise ValueError("invalid hook registration")
                matcher = entry.get("matcher", "")
                rx = re.compile(matcher or ".*")
                for hook in entry["hooks"]:
                    if not isinstance(hook, dict):
                        raise ValueError("invalid hook command")
                    expected = 'bash "$HOME/.claude/hooks/tripwire-run.sh" ' + script
                    # A filename mentioned in an echo/comment is not an installed hook.
                    if hook.get("type") == "command" and hook.get("command") == expected and not hook.get("async"):
                        covered.update(t for t in tools if rx.fullmatch(t))
            missing = sorted(set(tools) - covered)
            if missing:
                critical(event + " missing effective Tripwire coverage: " + ", ".join(missing))
except Exception as e:
    critical("invalid/unreadable settings: " + type(e).__name__)
sys.exit(1 if failed else 0)
PYEOF
then FAIL=1; fi
done

echo; echo "-- Memory/instruction drift since baseline --"
if ! DRIFT="$(git -C "$CLAUDE_DIR" status --porcelain --ignored -uall -- "${INSTRUCTIONS[@]}" 2>/dev/null)"; then echo "CRITICAL: cannot inspect instruction status"; FAIL=1; fi
if [ -n "$DRIFT" ]; then
  echo "$DRIFT" | sed 's/^/  /'
  echo "$DRIFT" | grep -q '^.D' && echo "  NOTE: deletions above — confirm each one (poisoning can also be an erasure)."
  echo "  ^ review; if it is all yours, commit as the new baseline."
else echo "  clean — no changes."; fi

echo; echo "-- Poisoning tripwire (signatures in NEW content only) --"
TMPF="$(mktemp)" || exit 1
DIFF_FILE="$(mktemp)" || exit 1
LIST_FILE="$(mktemp)" || exit 1
trap 'rm -f "$TMPF" "$DIFF_FILE" "$LIST_FILE"' EXIT
if ! git -C "$CLAUDE_DIR" -c core.fsmonitor=false diff --no-ext-diff --no-textconv HEAD -- "${INSTRUCTIONS[@]}" > "$DIFF_FILE"; then
  echo "CRITICAL: cannot inspect instruction diff"; FAIL=1
fi
grep '^+' "$DIFF_FILE" | grep -v '^+++' > "$TMPF" || true
if ! git -C "$CLAUDE_DIR" ls-files --others -z -- "${INSTRUCTIONS[@]}" > "$LIST_FILE"; then
  echo "CRITICAL: cannot inventory new instructions"; FAIL=1
fi
while IFS= read -r -d '' f; do
  if ! cat "$CLAUDE_DIR/$f" >> "$TMPF"; then
    echo "CRITICAL: cannot read new instruction content"; FAIL=1
  fi
done < "$LIST_FILE"
if [ ! -s "$TMPF" ]; then echo "  no new content to scan."; else
HITS="$(python3 - "$TMPF" <<'PYEOF'
import sys, re
t = open(sys.argv[1], encoding="utf-8", errors="replace").read()
sigs = [
 (re.compile(r"ignore\s+(all\s+|any\s+)?(previous|prior|above|earlier)|desconsidere\s+(as\s+)?instru", re.I), "override"),
 (re.compile(r"you are now|new instructions|system prompt|developer message|novas instru", re.I), "reframing"),
 (re.compile(r"(never|do not|don'?t|nunca|n[ãa]o)\s+(tell|alert|inform|notify|mention|reveal|conte|avise|informe|mencione|revele)\b.{0,40}\b(user|owner|usu[áa]rio|dono|him|her|them|ele|ela)", re.I), "secrecy"),
 (re.compile("[\u200B\u200C\u200E\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF\u00AD\U000E0000-\U000E007F]"), "invisible unicode"),
 (re.compile(r"(send|post|upload|forward|envie|poste|encaminhe)\b.{0,60}\b(to|para)\b.{0,60}(https?://|@|webhook)", re.I), "exfiltration"),
 (re.compile(r"dangerously-skip-permissions|bypasspermissions|(always|sempre)\s+(approve|allow|aprove|permita)", re.I), "auto-approval"),
]
for rx, label in sigs:
    m = rx.search(t)
    if m: print(f"{label}: ...{t[max(0,m.start()-40):m.end()+40]!r}...")
PYEOF
)"
if [ "$?" -ne 0 ]; then echo "CRITICAL: instruction signature check failed"; FAIL=1; fi
if [ -n "$HITS" ]; then echo "  CRITICAL: signature(s) in NEW content — do NOT commit a baseline; run the scan protocol:"; echo "$HITS" | sed 's/^/    /'; FAIL=1
else echo "  OK    no signatures in new content."; fi; fi
rm -f "$TMPF"

[ -f "$CLAUDE_DIR/fence-alarms.log" ] && { echo; echo "-- Fence alarms (last 10) --"; tail -10 "$CLAUDE_DIR/fence-alarms.log" | sed 's/^/  /'; }

echo; [ "$FAIL" -eq 0 ] && echo "VERDICT: HEALTHY" || echo "VERDICT: CRITICAL PROBLEMS — act now"
exit "$FAIL"
