#!/usr/bin/env bash
# scan-instructions.sh — Poisoned instruction & memory scan
# AI AI Tripwire Protocol · Gauzzi & Co · client edition v1.0
#
# WHAT IT DOES: inventories EVERY file that gives persistent instructions to your
# AI assistant (CLAUDE.md, memories, agents, skills, hooks, settings, MCP configs),
# searches them for known prompt-injection signatures, audits permissions/hooks/MCP
# configuration, checks for persistence outside Claude (cron, shell rc files, git
# hooks, ssh) and sweeps session transcripts for exfiltration commands.
#
# WHAT IT DOES NOT DO: no LLM, no modifications, nothing sent anywhere. It only reads
# and writes a report to ~/security-scan/. Deterministic — an attacker cannot "talk"
# this script into anything.
#
# USAGE:  bash scan-instructions.sh                 # scans $HOME (depth 8)
#         bash scan-instructions.sh /other/folder   # extra folders
#         SCAN_MAXDEPTH=12 bash scan-instructions.sh
# Windows: run in Git Bash or WSL (home is %USERPROFILE%).
# Synced cloud folders (Drive/OneDrive/iCloud): reading may download "online-only"
# files — accept it, or exclude the path via EXCLUDE_EXTRA='pattern'.
set -uo pipefail

umask 077
FAIL=0
OUT_DIR="$HOME/security-scan"
if [ -L "$OUT_DIR" ]; then echo "ERROR: report directory must not be a symlink" >&2; exit 1; fi
mkdir -p "$OUT_DIR" && chmod 700 "$OUT_DIR" || exit 1
STAMP="$(date +%Y-%m-%d_%H%M)"
REPORT="$(mktemp "$OUT_DIR/report-$STAMP-XXXXXX")" || exit 1
LIST="$(mktemp "$OUT_DIR/files-$STAMP-XXXXXX")" || exit 1
MAXDEPTH="${SCAN_MAXDEPTH:-12}"
EXCLUDE_EXTRA="${EXCLUDE_EXTRA:-__none__}"
: > "$REPORT"; : > "$LIST"

log() { printf '%s\n' "$*" | tee -a "$REPORT"; }
hdr() { log ""; log "================================================================"; log "$*"; log "================================================================"; }

hdr "TRIPWIRE SCAN — $(date '+%Y-%m-%d %H:%M %Z') — host: $(hostname) — user: $(whoami)"
log "Report: $REPORT"
log "Inventory: $LIST"

# ---------------------------------------------------------------- A. INVENTORY
hdr "A. INVENTORY — files that instruct the AI (most recently modified first)"
PRUNE=( -path '*/node_modules' -o -path '*/.Trash' -o -path '*/Library/Caches' -o -path '*/Library/Containers' \
        -o -path '*/.npm' -o -path '*/.cache' -o -path '*/.cargo' -o -path '*/.rustup' -o -path '*/site-packages' \
        -o -path '*/.venv' -o -path '*/venv' -o -path '*/.git/objects' -o -path '*/Library/Application Support/Google' )

{
  # 1) instruction files of any AI tool, anywhere under home
  find "$HOME" "$@" -maxdepth "$MAXDEPTH" \( "${PRUNE[@]}" \) -prune -o -type f \( \
       -name 'CLAUDE.md' -o -name 'CLAUDE.local.md' -o -name 'MEMORY.md' -o -name 'HANDOFF.md' \
       -o -name 'AGENTS.md' -o -name 'GEMINI.md' -o -name '.cursorrules' -o -name '.windsurfrules' \
       -o -name 'copilot-instructions.md' -o -name 'SKILL.md' -o -name '.mcp.json' \
       -o -name 'claude_desktop_config.json' -o -path '*/.vscode/settings.json' -o -path '*/.vscode/mcp.json' -o -path '*/.cursor/mcp.json' -o -path '*/.github/instructions/*.md' -o -path '*/.github/prompts/*.md' -o -path '*/.windsurf/rules/*' -o -path '*/.gemini/settings.json' -o \( -name '*' -path '*/.git/hooks/*' -not -name '*.sample' \) -o \( -name '*.mdc' -path '*/.cursor/rules/*' \) \
       -o \( -name '*.md' -path '*/.claude/rules/*' \) \) -print 2>/dev/null
  # 2) everything inside .claude directories (global and per-project): agents, commands, skills, hooks, memory, settings
  find "$HOME/.claude" -maxdepth 6 -type f \( -name '*.md' -o -name '*.json' -o -name '*.py' -o -name '*.sh' -o -name '*.js' -o -name '*.ts' \) \
       -not -path '*/projects/*/*.jsonl' -not -path "$HOME/.claude/cache/*" -not -path '*/shell-snapshots/*' -not -path '*/file-history/*' \
       -not -path '*/paste-cache/*' -not -path '*/telemetry/*' -not -path '*/uploads/*' -not -path '*/sessions/*' -not -path '*/tool-results/*' -not -path '*/workflows/*' -not -path '*/subagents/*' -print 2>/dev/null
  find "$HOME" "$@" -maxdepth "$MAXDEPTH" \( "${PRUNE[@]}" \) -prune -o -type d -name '.claude' -not -path "$HOME/.claude" -print 2>/dev/null \
    | while IFS= read -r d; do find "$d" -maxdepth 4 -type f \( -name '*.md' -o -name '*.json' -o -name '*.py' -o -name '*.sh' -o -name '*.js' \) -print 2>/dev/null; done
  # 3) user-level configs
  for f in "$HOME/.claude.json" "$HOME/.codex/config.toml" "$HOME/.codex/instructions.md" "$HOME/.gemini/settings.json" "$HOME/.cursor/mcp.json" "$HOME/.codeium/windsurf/memories/global_rules.md" "$HOME/.codeium/windsurf/mcp_config.json" "$HOME/.claude/plugins/installed_plugins.json" \
           "$HOME/Library/Application Support/Claude/claude_desktop_config.json" "${APPDATA:-}/Claude/claude_desktop_config.json"; do
    [ -f "$f" ] && printf '%s\n' "$f"
  done
} 2>/dev/null | grep -v -E "$EXCLUDE_EXTRA" | sort -u > "$LIST"

TOTAL=$(wc -l < "$LIST" | tr -d ' ')
log "Files found: $TOTAL"
log ""
log "  MODIFIED             SIZE     SHA256(12)     PATH"
while IFS= read -r f; do
  [ -f "$f" ] || continue
  if stat -f '%Sm' -t '%Y-%m-%d %H:%M' "$f" >/dev/null 2>&1; then mt=$(stat -f '%Sm' -t '%Y-%m-%d %H:%M' "$f"); sz=$(stat -f '%z' "$f");
  else mt=$(stat -c '%y' "$f" | cut -c1-16); sz=$(stat -c '%s' "$f"); fi
  sha=$(shasum -a 256 "$f" 2>/dev/null | cut -c1-12)
  printf '  %s  %7s  %s   %s\n' "$mt" "$sz" "$sha" "$f"
done < "$LIST" | sort -r | tee -a "$REPORT" >/dev/null
log ""
log "  ^ Recent modifications YOU don't recognize are the first signal."
log "  (depth limit: $MAXDEPTH levels below \$HOME — deeper trees are not scanned; raise with SCAN_MAXDEPTH=16, or pass extra folders as arguments)"

# ---------------------------------------------------- B. SIGNATURES + HIDDEN CONTENT
hdr "B. PROMPT-INJECTION SIGNATURES + HIDDEN CONTENT (per file:line)"
python3 - "$LIST" <<'PYEOF' | tee -a "$REPORT"
import os
import re
import sys
import unicodedata

files = [l.rstrip("\n") for l in open(sys.argv[1], encoding="utf-8", errors="replace") if l.strip()]
# Signatures are bilingual (EN + PT-BR) on purpose: injections arrive in either language. They are a
# tripwire for lazy attackers, not a detector — the fence and the gates are the control. Whitespace
# (including line breaks) is collapsed before matching, and the text is also checked after NFKC
# normalization (fullwidth letters), so "ignore all<newline>previous instructions" still hits.
SIGS = [
 ("SECRECY / hide from the user",
  re.compile(r"\b(never|do not|don'?t|nunca|n[ãa]o)\s+(tell|alert|inform|notify|conte|avise|informe)\s+(the\s+|o\s+|a\s+)?(user|owner|human|operator|usu[áa]rio|dono)\b|"
             r"\b(never|do not|don'?t)\s+(mention|reveal|disclose)\s+(this|it|these\s+instructions)\s+to\s+(the\s+)?(user|owner|human)\b|"
             r"(keep\s+(this|it)\s+(secret|hidden)\s+from\s+the\s+user|without\s+(telling|informing|notifying)\s+the\s+user|"
             r"n[ãa]o\s+(mencione|revele|mostre)\s+(isso|isto)\s+(ao|para\s+o)\s+usu[áa]rio|sem\s+(avisar|informar)\s+o\s+usu[áa]rio)", re.I)),
 ("OVERRIDE / reframing",
  re.compile(r"(ignore|disregard|forget)\s+(all\s+|any\s+|the\s+|your\s+)?(previous|prior|above|earlier|preceding)\s+(instructions?|rules?|guidance|prompts?)|forget\s+(all\s+)?your\s+instructions|"
             r"\byou\s+are\s+now\s+(a|an|the|in)\b|\bnew\s+instructions\s*:|your\s+(new\s+)?system\s+prompt\s+is|from\s+now\s+on\s+(always|never)\s+\w+\s+without|"
             r"desconsidere\s+(as\s+)?(instru[çc][õo]es|regras)|ignore\s+(as\s+)?instru[çc][õo]es\s+anteriores|voc[êe]\s+agora\s+[ée]\s+(um|uma|o|a)\b|novas\s+instru[çc][õo]es\s*:", re.I)),
 ("AUTO-APPROVAL / no permission",
  re.compile(r"(always|automatically|sempre|automaticamente)\s+(approve|allow|accept|permit|aprove|permita|aceite)\b|"
             r"without\s+(asking\s+for\s+)?(confirmation|permission|approval)|do\s+not\s+ask\s+(for\s+)?(permission|confirmation)|"
             r"n[ãa]o\s+pe[çc]a\s+(permiss[ãa]o|confirma[çc][ãa]o)|dangerously-skip-permissions|bypasspermissions|\"defaultmode\"\s*:\s*\"bypass", re.I)),
 ("EXFILTRATION / send outward",
  re.compile(r"\b(send|post|upload|forward|transmit|exfiltrate|email|envie|poste|suba|encaminhe|transmita)\b.{0,40}\b(the\s+|o\s+|a\s+|os\s+|as\s+)?(contents?|files?|\.env|env\s+file|secrets?|keys?|tokens?|credentials?|passwords?|conversation|chat\s+history|history|memory|memories|source\s+code|repo(sitory)?|conte[úu]do|arquivos?|segredos?|chaves?|senhas?|credenciais|hist[óo]rico|mem[óo]ria|c[óo]digo)\b.{0,60}\b(to|para)\b.{0,60}(https?://|@|webhook|endpoint)|"
             r"!\[[^\[\]\r\n]*\]\(https?://[^)?&\s]*[?&][^)\s]*\)|"
             r"webhook\.site|hooks\.slack\.com|discord(app)?\.com/api/webhooks|ngrok(-free)?\.(io|app|dev)|pastebin\.com|transfer\.sh|ntfy\.sh|api\.telegram\.org|requestbin|pipedream\.net|burpcollaborator|oastify\.com|interact\.sh|trycloudflare\.com|0x0\.st|file\.io", re.I)),
 ("SECRET HARVESTING",
  re.compile(r"(collect|gather|read|copy|include|extract|colete|leia|copie|inclua|extraia)\b.{0,50}\b(api[_ -]?keys?|tokens?|passwords?|secrets?|credentials?|\.env\b|id_rsa|id_ed25519|private\s+key|senhas?|credenciais|chaves?\s+(de\s+)?api)\b.{0,60}\b(and|then|e|depois)\s+(send|post|upload|email|envie|poste|suba)", re.I)),
 ("PERSISTENCE / write to memory",
  re.compile(r"(remember|memorize|store|save|lembre|memorize|guarde|salve)\s+(this|that|the\s+following|these|isso|isto|o\s+seguinte)\b.{0,60}\b(memory|mem[óo]ria|CLAUDE\.md|MEMORY\.md|preferences?|prefer[êe]ncias)\b|"
             r"(add|append|write|adicione|acrescente|escreva)\s+(this|the\s+following|these\s+instructions|isso|isto)\s+(to|into|em|no|na)\s+(your\s+)?(memory|mem[óo]ria|CLAUDE\.md|MEMORY\.md|settings)", re.I)),
 ("GUARDRAIL SABOTAGE",
  re.compile(r"(disable|remove|delete|bypass|turn\s+off|comment\s+out|desative|remova|apague|contorne|desligue)\s+(the\s+|all\s+|os\s+|as\s+|o\s+|a\s+)?(hooks?|guards?|guardrails?|safety\s+(checks?|hooks?)|security\s+(hooks?|checks?)|permission\s+(prompts?|checks?)|approval|confirma[çc][õo]es|permiss[õo]es)\b", re.I)),
 ("INSTRUCTION ADDRESSED TO THE ASSISTANT",
  re.compile(r"\byou\s+(must|should|need\s+to|are\s+to|will|shall|have\s+to)\s+(now\s+|immediately\s+|first\s+)?(run|execute|send|forward|delete|download|open|install|approve|exfiltrate|copy)\b|"
             r"\b(assistant|claude|agent|copilot|ai)\s*[:,]\s*(please\s+)?(run|execute|send|forward|delete|download|open|install|approve)\b|"
             r"\b(note|instructions?|message|task)\s+(to|for)\s+the\s+(assistant|agent|ai|model)\b|"
             r"\bvoc[êe]\s+(deve|precisa|tem\s+que)\s+(agora\s+)?(executar|rodar|enviar|encaminhar|apagar|baixar|abrir|instalar|aprovar|copiar)\b|"
             r"\b(assistente|agente)\s*[:,]\s*(por\s+favor\s+)?(execute|rode|envie|encaminhe|apague|baixe|abra|instale|aprove)\b", re.I)),
]
ZW = re.compile("[\u200B\u200C\u200E\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF\u00AD\u2028\u2029\u180E\u3164\u115F\u1160\U000E0000-\U000E007F\U000E0100-\U000E01EF]")
EMOJI_LIKE = re.compile("[\U0001F000-\U0001FAFF\u2600-\u27BF\U0001F1E6-\U0001F1FF\uFE0F\U0001F3FB-\U0001F3FF\u200D]")
B64 = re.compile(r"(?:[A-Za-z0-9+/_-]{60,}={0,2}(?:\s*\n\s*[A-Za-z0-9+/_-]{60,}={0,2}){1,}|[A-Za-z0-9+/_-]{120,}={0,2})")



def hidden_blocks(text):
    """Forward-only paired delimiters; an unterminated opener never retries its suffix."""
    pairs = [
        (re.compile(r"<!--"), re.compile(r"-->")),
        (re.compile(r"\[//\]:[ \t]*#[ \t]*\("), re.compile(r"\)")),
        (re.compile(r"<details\b[^<>]*>", re.I), re.compile(r"</details\s*>", re.I)),
    ]
    for opening, closing in pairs:
        cursor = 0
        while True:
            start = opening.search(text, cursor)
            if not start:
                break
            end = closing.search(text, start.end())
            if not end:
                yield start.start(), text[start.start():]
                break
            yield start.start(), text[start.start():end.end()]
            cursor = end.end()


def count_invisible(t):
    """Invisible/bidi/tag characters, plus zero-width joiners that are NOT inside an emoji sequence."""
    n = len(ZW.findall(t))
    for m in re.finditer("\u200D", t):
        b, a = t[m.start() - 1:m.start()], t[m.end():m.end() + 1]
        if not (b and EMOJI_LIKE.match(b) and a and EMOJI_LIKE.match(a)):
            n += 1
    return n


def line_of(text, pos):
    return text.count("\n", 0, pos) + 1


hits = 0
hidden = 0
for f in files:
    try:
        if os.path.getsize(f) > 5_000_000:
            print(f"  [skipped >5MB] {f}")
            continue
        text = open(f, encoding="utf-8", errors="replace").read()
    except Exception as e:
        print(f"  [read error] {f}: {e}")
        continue
    # same length as text, so match offsets map back to line numbers; line breaks no longer split a phrase
    flat = text.replace("\n", " ").replace("\r", " ").replace("\t", " ")
    variants = [("", flat)]
    nfkc = unicodedata.normalize("NFKC", flat)
    if nfkc != flat:
        variants.append((" (after NFKC normalization)", nfkc))
    seen = set()
    for suffix, body in variants:
        for label, rx in SIGS:
            for m in rx.finditer(body):
                ln = line_of(text, min(m.start(), len(text) - 1)) if not suffix else "?"
                key = (label, ln)
                if key in seen:
                    continue
                seen.add(key)
                hits += 1
                snip = body[max(0, m.start() - 50):m.end() + 50].strip()[:220]
                print(f"  [{label}] {f}:{ln}{suffix}\n      {snip}")
    zw = count_invisible(text)
    if zw:
        hidden += 1
        print(f"  [HIDDEN: {zw} invisible/bidi/tag character(s)] {f}  <- invisible to humans, readable by the AI")
    if f.lower().endswith((".md", ".mdc", ".txt", ".cursorrules", ".windsurfrules")):
        for position, body in hidden_blocks(text):
            if len(body) > 30:
                hidden += 1
                print(f"  [HIDDEN: HTML/markdown comment or collapsed block, {len(body)} chars] {f}:{line_of(text, position)}\n      {body[:200].replace(chr(10), ' ')}")
        longl = [i for i, l in enumerate(text.splitlines(), 1) if re.search(r"[ \t]{60,}\S", l) or len(l) > 3000]
        if longl:
            hidden += 1
            print(f"  [HIDDEN: line(s) with whitespace padding or >3000 chars — can hide instructions off-screen] {f}: lines {longl[:5]}")
    if B64.search(text) and not f.endswith((".json", ".jsonl", ".png", ".svg", ".lock")):
        hidden += 1
        print(f"  [HIDDEN: long base64/base64url blob (possibly MIME-wrapped)] {f}")
print(f"\n  TOTAL: {hits} textual signature(s), {hidden} hidden-content indicator(s).")
print("  False positives are expected (a security hook QUOTES the very signatures). Signatures are a tripwire for unsophisticated payloads, not a detector: judge each hit in context (Phase 2).")
PYEOF
if [ "$?" -ne 0 ]; then log "ERROR: audit section incomplete"; FAIL=1; fi

# ----------------------------------------------------------- C. CONFIG / HOOKS / MCP
hdr "C. CONFIGURATION AUDIT — permissions, hooks, MCP servers, plugins"
python3 - "$LIST" <<'PYEOF' | tee -a "$REPORT"
import sys, json, os, re, hashlib, glob
home = os.path.expanduser("~")
files = [l.rstrip("\n") for l in open(sys.argv[1], encoding="utf-8", errors="replace") if l.strip()]
invalid = False
def bad(label):
    global invalid
    invalid = True
    print(f"  INVALID configuration: {label} — audit incomplete for this value")
def mapping(value, label):
    if not isinstance(value, dict):
        bad(label); return {}
    return value
def sequence(value, label):
    if not isinstance(value, list):
        bad(label); return []
    return value
def load(p):
    try: return mapping(json.load(open(p, encoding="utf-8")), p)
    except Exception as e:
        bad(f"{p}: {type(e).__name__}"); return {}
def sha(p):
    try: return hashlib.sha256(open(p,"rb").read()).hexdigest()[:12]
    except Exception: return "?"
settings = [p for p in files if re.search(r"/\.claude/settings(\.local)?\.json$", p)]
for p in settings:
    d = load(p); print(f"\n  SETTINGS: {p}")
    perm = mapping(d.get("permissions", {}), p + ".permissions")
    print(f"    defaultMode: {perm.get('defaultMode', '(default)')}")
    for k in ("allow", "deny", "ask"):
        v = sequence(perm.get(k, []), p + ".permissions." + k)
        if v: print(f"    permissions.{k} ({len(v)}): " + "; ".join(map(str, v))[:900])
    broad = [r for r in sequence(perm.get("allow", []), p + ".permissions.allow") if re.search(r"Bash\(\*?\)|Bash\(\*\)|^Bash$|Bash\((python|bash|sh|zsh|node|curl|wget|scp|rclone|rm|eval|nc)\b|^WebFetch$|^mcp__\*|mcp__[^_]+__\*", str(r))]
    for k in ("disableAllHooks", "apiKeyHelper", "enableAllProjectMcpServers", "statusLine", "env"):
        if k in d: print(f"    !! {k}: {json.dumps(d[k])[:300]}  <- verify you set this (env can redirect ALL traffic: ANTHROPIC_BASE_URL)")
    if broad: print(f"    !! BROAD ALLOW (review): {broad}")
    hooks = mapping(d.get("hooks", {}), p + ".hooks")
    for ev, entries in hooks.items():
        for e in sequence(entries, p + ".hooks." + ev):
            e = mapping(e, p + ".hook entry")
            for h in sequence(e.get("hooks", []), p + ".hook commands"):
                h = mapping(h, p + ".hook command")
                cmd = h.get("command", "")
                if not isinstance(cmd, str):
                    bad(p + ".hook command string"); continue
                print(f"    HOOK {ev} [{e.get('matcher','*')}]: {cmd}")
                for path in re.findall(r"(\S+\.(?:py|sh|js|ts|rb|pl))", cmd):
                    path = os.path.expandvars(path.replace("$HOME", home).replace("~", home)).strip('"\'')
                    if os.path.exists(path):
                        head = open(path, encoding="utf-8", errors="replace").read(400).replace("\n", " | ")
                        print(f"      -> {path}  sha256:{sha(path)}\n         head: {head[:300]}")
                    else:
                        print(f"      -> !! HOOK FILE DOES NOT EXIST: {path}")
                if re.search(r"curl|wget|nc |base64|python -c|eval|\$\(", cmd) and not re.search(r"\.(py|sh|js)\b", cmd):
                    print("      !! INLINE HOOK with network/eval — every hook runs on EVERY tool call: read it carefully")
cj = os.path.join(home, ".claude.json")
if os.path.exists(cj):
    d = load(cj); print(f"\n  USER CONFIG: {cj}")
    def show_mcp(servers, scope):
        for name, cfg in mapping(servers, scope + ".mcpServers").items():
            cfg = mapping(cfg, scope + ".server." + name)
            tgt = cfg.get("command") or cfg.get("url") or cfg.get("httpUrl") or ""
            args = re.sub(r"[A-Za-z0-9_\-]{24,}", "<redacted>", " ".join(map(str, sequence(cfg.get("args", []), "MCP args"))))
            print(f"    MCP [{scope}] {name}: {tgt} {args}"[:300])
    show_mcp(d.get("mcpServers", {}), "user")
    for proj, pd in mapping(d.get("projects", {}), cj + ".projects").items():
        if isinstance(pd, dict) and pd.get("mcpServers"): show_mcp(pd["mcpServers"], f"project {proj}")
        if isinstance(pd, dict) and pd.get("allowedTools"): print(f"    allowedTools [{proj}]: {pd['allowedTools']}"[:400])
for p in files:
    if p.endswith((".mcp.json", "claude_desktop_config.json")):
        d = load(p); print(f"\n  MCP FILE: {p}")
        for name, cfg in mapping(d.get("mcpServers", {}), p + ".mcpServers").items():
            cfg = mapping(cfg, p + ".server." + name)
            print(f"    MCP {name}: {cfg.get('command') or cfg.get('url')} {' '.join(map(str, sequence(cfg.get('args', []), 'MCP args')))}"[:300])
plug = os.path.join(home, ".claude", "plugins")
if os.path.isdir(plug):
    print(f"\n  PLUGINS in {plug}:")
    for root in sorted(glob.glob(os.path.join(plug, "*"))): print(f"    {root}")
print("\n  Review: every MCP/plugin/hook you did NOT consciously install is suspect. Hooks execute code on every tool call.")
sys.exit(1 if invalid else 0)
PYEOF
if [ "$?" -ne 0 ]; then log "ERROR: audit section incomplete"; FAIL=1; fi

# ------------------------------------------------- D. PERSISTENCE OUTSIDE CLAUDE
hdr "D. PERSISTENCE OUTSIDE CLAUDE — cron, launch agents, shell rc, git, ssh, binary"
log "-- The 'claude' binary (an alias/wrapper in front of the real binary is a vector) --"
type claude 2>&1 | head -3 | tee -a "$REPORT" >/dev/null
command -v -a claude 2>/dev/null | tee -a "$REPORT" >/dev/null
log "-- crontab --"; (crontab -l 2>/dev/null || echo "  (empty)") | tee -a "$REPORT" >/dev/null
if [ -d "$HOME/Library/LaunchAgents" ]; then
  log "-- LaunchAgents (macOS) --"
  for f in "$HOME"/Library/LaunchAgents/*.plist; do [ -f "$f" ] && log "  $f" && grep -A3 -i "ProgramArguments" "$f" 2>/dev/null | grep -o "<string>.*</string>" | head -4 | sed 's/^/      /' | tee -a "$REPORT" >/dev/null; done
fi
[ -d "$HOME/.config/systemd/user" ] && { log "-- systemd user units --"; ls -la "$HOME/.config/systemd/user" | tee -a "$REPORT" >/dev/null; }
log "-- Shell rc files (suspicious lines: network, base64, eval, claude alias) --"
for f in "$HOME/.zshrc" "$HOME/.zprofile" "$HOME/.zshenv" "$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.profile"; do
  [ -f "$f" ] || continue
  mt=$(stat -f '%Sm' -t '%Y-%m-%d' "$f" 2>/dev/null || stat -c '%y' "$f" | cut -c1-10)
  log "  $f (modified $mt)"
  grep -nE 'curl|wget|base64|eval |nc |/dev/tcp|python[3]? -c|alias claude=|claude\(\)|PROMPT_COMMAND|precmd|ANTHROPIC_BASE_URL|ANTHROPIC_AUTH_TOKEN|NODE_OPTIONS|--require|LD_PRELOAD|DYLD_INSERT|^source |^\. ' "$f" 2>/dev/null | sed 's/^/      /' | tee -a "$REPORT" >/dev/null
done
log "-- Global git config (hooksPath/templateDir/includes are silent-execution vectors) --"
git config --global --list 2>/dev/null | grep -iE 'hookspath|templatedir|include|credential|url\.' | sed 's/^/  /' | tee -a "$REPORT" >/dev/null || log "  (none)"
log "-- SSH --"
[ -f "$HOME/.ssh/authorized_keys" ] && log "  authorized_keys: $(wc -l < "$HOME/.ssh/authorized_keys" | tr -d ' ') key(s), modified $(stat -f '%Sm' -t '%Y-%m-%d' "$HOME/.ssh/authorized_keys" 2>/dev/null || stat -c '%y' "$HOME/.ssh/authorized_keys" | cut -c1-10)"
[ -f "$HOME/.ssh/config" ] && grep -nE 'ProxyCommand|LocalCommand|PermitLocalCommand' "$HOME/.ssh/config" 2>/dev/null | sed 's/^/  ssh config: /' | tee -a "$REPORT" >/dev/null
log "-- Git remotes of every repository (a remote you don't recognize = exfiltration by push) --"
find "$HOME" "$@" -maxdepth "$MAXDEPTH" \( "${PRUNE[@]}" \) -prune -o -type d -name '.git' -print 2>/dev/null | while IFS= read -r g; do
  r="$(dirname "$g")"; git -C "$r" remote -v 2>/dev/null | awk -v repo="$r" '/\(push\)/{print "  " $2 "   <- " repo}'
done | sort -u | tee -a "$REPORT" >/dev/null

# ------------------------------------------------- E. SESSION FORENSICS
hdr "E. SESSION FORENSICS — exfiltration commands executed in the last 60 days"
PAT='curl [^;|]*(-d ?@|--data|-F ?|-T ?|--upload-file|-X ?(POST|PUT)|--json|\$\(|`)|wget [^;|]*--post|gws gmail \+(send|reply|forward)|mcp__[A-Za-z_]*(send|share|publish|post|push|upload)[A-Za-z_]*|\bscp |\brsync [^;|]*@|\brclone (copy|sync|move)|aws s3 (cp|sync)|gsutil (cp|rsync)|gh gist create|webhook\.site|hooks\.slack\.com|discord(app)?\.com/api/webhooks|ngrok|pastebin\.com|transfer\.sh|ntfy\.sh|api\.telegram\.org|dangerously-skip-permissions|base64 [^;|]*\| *curl|/dev/tcp/'
if ! printf '' | grep -E "$PAT" >/dev/null; then
  # grep returns 1 for no match and 2 for an invalid pattern.
  printf '' | grep -E "$PAT" >/dev/null
  RC=$?
  if [ "$RC" -gt 1 ]; then log "ERROR: invalid forensic pattern"; exit 1; fi
fi
log "  (this section greps every transcript of the last 60 days; on a heavy machine it can take several minutes — transcripts over 80 MB are skipped and listed)"
if [ -d "$HOME/.claude/projects" ]; then
  find "$HOME/.claude/projects" -name '*.jsonl' -mtime -60 -size +80M 2>/dev/null | sed 's/^/  SKIPPED (>80MB, grep it manually): /' | tee -a "$REPORT" >/dev/null
  find "$HOME/.claude/projects" -name '*.jsonl' -mtime -60 -size -80M 2>/dev/null | while IFS= read -r t; do
    n=$(grep -cE "$PAT" "$t"); RC=$?
    if [ "$RC" -gt 1 ]; then log "ERROR: cannot scan transcript $t"; exit 1; fi
    [ "${n:-0}" -gt 0 ] && log "  $n occurrence(s) in $t" && grep -oE ".{0,80}($PAT).{0,120}" "$t" | head -5 | sed 's/^/      /' | tee -a "$REPORT" >/dev/null
    :
  done || { log "ERROR: transcript audit incomplete"; exit 1; }
  log "  (end — if nothing appeared above, no recent transcript contains these patterns)"
fi
[ -f "$HOME/.claude/fence-alarms.log" ] && { log "-- Tripwire alarms (fence-alarms.log, last 20) --"; tail -20 "$HOME/.claude/fence-alarms.log" | sed 's/^/  /' | tee -a "$REPORT" >/dev/null; }

# ------------------------------------------------------------- F. SUMMARY
hdr "F. NEXT STEPS"
log "  1. Read section B: each hit is [category] file:line. Open the file and judge the context."
log "  2. Read section C: any hook/MCP/plugin/allow you did not install = suspect."
log "  3. Read section D: unknown cron, rc lines, git hooksPath, remotes or authorized_keys = compromise beyond the AI."
log "  4. Run Phase 2 of the protocol (Claude-assisted review) with THIS report as input."
log "  5. Do NOT delete anything yet — move it to quarantine (it is evidence). Then rotate secrets."
log ""
log "Report saved to: $REPORT"

exit "$FAIL"
