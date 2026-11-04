#!/usr/bin/env python3
"""
guard-irreversible.py — AI Tripwire · Layer A (PreToolUse) · Gauzzi & Co open-source edition v1.1

Forces an explicit approval prompt ("ask") BEFORE any action that:
  (1) sends data out — email, file sharing, HTTP POST/upload, ANY network request that carries
      local data (command substitution, variables, @file, stdin redirects), inline network scripts
      (python -c / node -e / …), file transfer to a server or cloud bucket, DNS lookups built from
      local data, git push to an unknown remote, MCP tools that send/share/publish/create/post;
  (2) is irreversible — delete, force-push, format, destroy cloud resources;
  (3) modifies Claude's own defenses or the machine's persistence by ANY means — the Edit/Write
      tools, shell redirection, or write-capable commands (mv, cp, tee, ln, sed -i, python -c …)
      aimed at hooks, settings, agents, skills, memories, CLAUDE.md, shell rc files, git config,
      ssh, cron/launchd.
And DENIES outright what is never legitimate in a normal session: disabling permissions, sending
data to webhook/paste services, encode-and-send, netcat/socat (by any path), deleting the hooks.

v1.1 (after external review): every gate is evaluated on the WHOLE command and a benign clause can
no longer short-circuit the decision — `gws gmail +send --to you@… ; aws s3 cp …` asks because of
the second clause, even though the first is allowed. The final decision is: deny > ask > allow.

Known limits, stated honestly: a static GET with no local data (curl https://example.com) is
allowed; heavily obfuscated shell can evade regexes — that is why layers B and C exist, and why
OS-level immutability (chmod 444 / chflags uchg on the hooks) or Claude Code's managed settings
are the enforcement layer for teams. FAILS CLOSED: any error becomes an approval prompt.

Install: ~/.claude/hooks/guard-irreversible.py + the "hooks" block in settings.json.
Edit the CONFIG block below before use.
"""

import json
import os
import re
import shlex
import subprocess
import sys
import time
from urllib.parse import urlsplit

# ------------------------------------------------------------------ CONFIG
OWNER_EMAILS = {"you@yourcompany.com"}  # mail sent only to yourself passes without asking
ALLOWED_GIT_REMOTES = re.compile(
    r"github\.com[:/](YOUR-ORG|your-username)/", re.I
)  # push allowed; everything else asks
GATE_SECRET_READS = True  # ask when a command reads .env / keys / keychain
# Files whose modification is self-modification or machine persistence (checked on the Edit/Write
# tools' file_path AND on the text of shell commands).
PROTECTED_PATHS = re.compile(
    r"/\.claude/(hooks|agents|commands|skills|plugins|memory|rules)/|/\.claude/projects/[^/]+/memory/|/\.claude/settings[^/]*\.json$|"
    r"/CLAUDE(\.local)?\.md$|/MEMORY\.md$|/\.claude\.json$|/\.mcp\.json$|/claude_desktop_config\.json$|"
    r"/\.(zshrc|zprofile|zshenv|bashrc|bash_profile|profile|gitconfig|npmrc|netrc)$|/\.ssh/|/\.aws/|"
    r"/Library/LaunchAgents/|/\.config/systemd/|/\.cursor/rules/|/\.cursorrules$|/AGENTS\.md$|/copilot-instructions\.md$|/\.vscode/(settings|mcp)\.json$|"
    r"/\.claude/\.gitignore$|/\.claude/fence-alarms\.log$|/\.claude/\.git/|/\.claude/tripwire\.json$|/\.claude/plugins/|/\.cursor/mcp\.json$|/\.codeium/|/\.windsurf/|/\.github/(instructions|prompts|agents|chatmodes)/|/\.git/hooks/",
    re.I,
)
PROTECTED_IN_CMD = re.compile(
    r"\.claude/(hooks|agents|commands|skills|plugins|memory|rules|settings[^/\s'\"]*\.json|projects/[^/\s]+/memory)"
    r"|/claude(\.local)?\.md\b|/memory\.md\b|\.claude\.json\b|\.mcp\.json\b|claude_desktop_config\.json"
    r"|\.(zshrc|zprofile|zshenv|bashrc|bash_profile|profile|gitconfig|npmrc|netrc)\b|/\.ssh/|/\.aws/|"
    r"library/launchagents/|\.config/systemd/|\.cursor/rules/|\.cursorrules\b|/agents\.md\b|copilot-instructions\.md|\.vscode/(settings|mcp)\.json|"
    r"fence-alarms\.log|\.claude/\.git\b|tripwire\.json|\.cursor/mcp\.json|\.codeium/|\.windsurf/|\.github/(instructions|prompts|agents|chatmodes)/|\.git/hooks/",
    re.I,
)
# Commands that can write/replace a file (a protected path + one of these = self-modification).
WRITE_VERBS = re.compile(
    r"(^|[\s;&|(`/])(rm|rmdir|mv|cp|tee|ln|install|rsync|truncate|touch|chmod|chown|chflags|dd|patch|unlink|shred|"
    r"sed\s+-[a-z]*i|perl\s+-[a-z]*i|python3?\s+-c|node\s+-e|ruby\s+-e|perl\s+-e|php\s+-r|"
    r"git\s+(checkout|restore|apply|stash)|chattr|curl\s.*\s-o\s|wget\s.*\s-O\s)",
    re.I,
)
_CONFIG_ERROR = ""

# Optional overrides read from ~/.claude/tripwire.json (written once by install.sh; upgrades never touch it):
#   {"owner_emails": ["you@x.com"], "allowed_git_remotes": "github\\.com[:/]YOUR-ORG/", "gate_secret_reads": true}
try:
    with open(os.path.expanduser("~/.claude/tripwire.json"), encoding="utf-8") as _cf:
        _cfg = json.load(_cf)
    if not isinstance(_cfg, dict):
        raise ValueError("config must be an object")
    _owners = _cfg.get("owner_emails", list(OWNER_EMAILS))
    _remotes = _cfg.get("allowed_git_remotes", ALLOWED_GIT_REMOTES.pattern)
    _reads = _cfg.get("gate_secret_reads", GATE_SECRET_READS)
    if not isinstance(_owners, list) or not all(
        isinstance(e, str) and re.fullmatch(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", e) for e in _owners
    ):
        raise ValueError("owner_emails must be a list of literal addresses")
    if not isinstance(_remotes, str) or not _remotes or not isinstance(_reads, bool):
        raise ValueError("invalid gate configuration")
    _compiled = re.compile(_remotes, re.I)
    OWNER_EMAILS, ALLOWED_GIT_REMOTES, GATE_SECRET_READS = set(_owners), _compiled, _reads
except FileNotFoundError:
    pass
except Exception as _e:  # a broken config must not silently weaken the gate: keep defaults, say so in the first ask
    _CONFIG_ERROR = f"(tripwire.json unreadable: {type(_e).__name__}; using built-in defaults) "
# ---------------------------------------------------------------------------


def _out(decision, reason):
    print(
        json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": decision,
                    "permissionDecisionReason": reason,
                }
            }
        )
    )
    sys.exit(0)


def deny(reason):
    _out("deny", "BLOCKED by Tripwire: " + reason)


def allow():
    if _CONFIG_ERROR:
        _out("ask", _CONFIG_ERROR + "Repair the configuration before using policy exceptions.")
    sys.exit(0)


def path_forms(path, cwd):
    """Check lexical names and symlink targets without executing shell expansion."""
    path = path.replace("\\", "/").replace("${HOME}", os.path.expanduser("~")).replace("$HOME", os.path.expanduser("~"))
    path = os.path.expanduser(path)
    if not os.path.isabs(path):
        path = os.path.join(cwd, path)
    return {os.path.normpath(path), os.path.realpath(path)}


def protected_path(path, cwd):
    return any(
        PROTECTED_PATHS.search(p)
        or PROTECTED_PATHS.search(p.rstrip("/") + "/")
        or p.rstrip("/").lower().endswith("/.claude")
        for p in path_forms(path, cwd)
    )


def literal_command(cmd):
    """Exceptions apply only to one static command, never to shell programs."""
    quote = None
    for char in cmd:
        if quote == "'":
            if char == "'":
                quote = None
            continue
        if char == '"' and quote in {None, '"'}:
            quote = None if quote else '"'
            continue
        if char == "'" and quote is None:
            quote = "'"
            continue
        if char in "$" + chr(96) + "\\\n\r" or (quote is None and char in ";&|<>(){}*?[]#"):
            return []
    try:
        return shlex.split(cmd)
    except ValueError:
        return []


def owner_send(cmd):
    args = literal_command(cmd)
    if args[:3] != ["gws", "gmail", "+send"]:
        return False
    recipients = []
    i = 3
    while i < len(args):
        flag, eq, value = args[i].partition("=")
        if flag not in {"--to", "--cc", "--bcc", "--subject", "--body"}:
            return False
        if not eq:
            i += 1
            if i >= len(args):
                return False
            value = args[i]
        if flag in {"--to", "--cc", "--bcc"}:
            parts = value.split(",")
            if not all(re.fullmatch(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", p) for p in parts):
                return False
            recipients.extend(p.lower() for p in parts)
        i += 1
    return bool(recipients) and set(recipients) <= {e.lower() for e in OWNER_EMAILS}


def trusted_remote(url):
    """A trusted host mentioned in an attacker path is not a trusted authority."""
    if re.search(r"[\s\\%?#]", url):
        return False
    if "://" in url:
        parsed = urlsplit(url)
        if parsed.scheme not in {"ssh", "https"} or not parsed.hostname or parsed.port:
            return False
        if parsed.password or (parsed.scheme == "https" and parsed.username):
            return False
        host, path = parsed.hostname, parsed.path.lstrip("/")
    else:
        match = re.fullmatch(r"(?:git@)?([a-zA-Z0-9.-]+):([^\s:]+)", url)
        if not match:
            return False
        host, path = match.groups()
    if any(p in {"", ".", ".."} for p in path.split("/")):
        return False
    return bool(ALLOWED_GIT_REMOTES.match(host.lower() + "/" + path))


def trusted_push(cmd, cwd):
    args = literal_command(cmd)
    # Implicit defaults, context overrides, direct URLs and push flags need approval.
    if len(args) < 3 or args[:2] != ["git", "push"]:
        return False
    remote = args[2]
    if not re.fullmatch(r"[a-zA-Z0-9_][a-zA-Z0-9._-]*", remote):
        return False
    if any(arg.startswith(("-", "+", ":")) for arg in args[3:]):
        return False
    try:
        result = subprocess.run(
            ["git", "-C", cwd, "remote", "get-url", "--push", "--all", remote],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
        urls = result.stdout.splitlines()
        return result.returncode == 0 and bool(urls) and all(trusted_remote(url) for url in urls)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return False


def temporary_delete(cmd, cwd):
    args = literal_command(cmd)
    if not args or os.path.basename(args[0]) not in {"rm", "rmdir"}:
        return False
    paths = []
    options = True
    for arg in args[1:]:
        if options and arg == "--":
            options = False
        elif options and arg.startswith("-"):
            continue
        else:
            paths.append(arg)
    roots = {os.path.realpath(p) for p in ("/tmp", "/private/tmp", "/var/folders", "/private/var/folders")}
    return bool(paths) and all(
        os.path.isabs(p)
        and not protected_path(p, cwd)
        and any(os.path.realpath(p).startswith(root + "/") for root in roots)
        for p in paths
    )


def shell_protected_write(cmd, cwd, git_mutation=False):
    """Conservative canonical targets and possible cd contexts, not a shell sandbox."""
    try:
        lexer = shlex.shlex(cmd, posix=True, punctuation_chars=";&|()<>")
        lexer.whitespace_split = True
        tokens = list(lexer)
    except ValueError:
        return True
    if len(tokens) > 256:
        return True
    contexts = {os.path.realpath(cwd)}
    for i, tok in enumerate(tokens[:-1]):
        if tok in {"cd", "pushd"}:
            j = i + 1
            while j < len(tokens) and tokens[j] in {"-L", "-P", "-e"}:
                j += 1
            if j < len(tokens) and tokens[j] == "--":
                j += 1
            destination = tokens[j] if j < len(tokens) and tokens[j] not in {";", "&&", "||", "|", ")"} else "~"
            if destination.startswith("-"):
                return True  # directory-stack state is not available to the hook
            for base in list(contexts):
                contexts.update(path_forms(destination, base))
                if len(contexts) > 8:
                    return True
    if git_mutation and any("/.claude/" in base.lower() or base.lower().endswith("/.claude") for base in contexts):
        return True
    # Downloads are writes too; retain attached/long option values as destinations.
    if any(os.path.basename(token) in {"curl", "wget"} for token in tokens):
        for i, token in enumerate(tokens):
            if token in {"--remote-name", "--remote-name-all", "--remote-header-name", "-O", "-J"}:
                return True  # destination determined by the remote, not a reviewed literal
            target = None
            if token in {"-o", "-O", "--output", "--output-document", "--output-dir", "--directory-prefix", "-P"}:
                target = tokens[i + 1] if i + 1 < len(tokens) else ""
            elif token.startswith(("--output=", "--output-document=", "--output-dir=", "--directory-prefix=")):
                target = token.split("=", 1)[1]
            elif token.startswith(("-o", "-O", "-P")) and len(token) > 2:
                target = token[2:]
            if target is not None and (not target or any(protected_path(target, base) for base in contexts)):
                return True
    for i, tok in enumerate(tokens[:-1]):
        if ">" in tok and set(tok) <= set("<>&|"):
            if any(protected_path(tokens[i + 1], base) for base in contexts):
                return True
    if WRITE_VERBS.search(" ".join(tokens)) or git_mutation:
        return any(
            protected_path(token.split("=", 1)[-1], base)
            for token in tokens
            for base in contexts
            if token and token not in {";", "&&", "||", "|"}
        )
    return False


def canonical_secret_read(cmd, cwd):
    if not re.search(r"(^|[\s;&|/])(cat|less|more|head|tail|grep|rg|sed|awk|cp|base64|xxd|od|strings)\s", cmd):
        return False
    try:
        tokens = shlex.split(cmd)
    except ValueError:
        return True
    secrets = re.compile(
        r"(^|/)(\.env(?:\.[^/]*)?|id_rsa|id_ed25519|\.netrc|\.npmrc|\.git-credentials)$|/\.aws/credentials$|\.(pem|p12|key)$",
        re.I,
    )
    return any(secrets.search(p) for token in tokens for p in path_forms(token, cwd))


def main():
    try:
        raw = sys.stdin.read(2_000_001)
        if len(raw) > 2_000_000:
            _out("ask", "Hook input exceeds the inspection limit; review this operation.")
        data = json.loads(raw)
    except Exception:
        _out(
            "ask",
            "guard-irreversible could not parse its input — FAILING CLOSED. Approve consciously, or fix/disable the hook in settings.json.",
        )

    tool = data.get("tool_name", "") or ""
    tin = data.get("tool_input", {}) or {}
    cwd = data.get("cwd") or os.getcwd()
    asks = []  # every gate appends; the decision is made once, at the end

    # ---- 0) Edit/Write tools on protected files (defenses, instructions, machine persistence)
    if tool in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        path = (tin.get("file_path") or tin.get("notebook_path") or "").replace("\\", "/")
        if protected_path(path, cwd):
            _out(
                "ask",
                "This modifies a PROTECTED file (instructions / defenses / machine persistence): "
                + path
                + ". An injection persists exactly this way. Approve only if YOU asked for this edit.",
            )
        allow()

    # ---- 1) Non-Bash tools (MCP, Artifact, …): decide by name — outbound-capable names ask
    if tool != "Bash":
        n = tool.lower()
        if n == "webfetch":
            url = str(tin.get("url") or "")
            if re.search(
                r"webhook\.site|hooks\.slack\.com|discord(app)?\.com/api/webhooks|ngrok|trycloudflare|loca\.lt|serveo|0x0\.st|file\.io|requestbin|pipedream|beeceptor|requestcatcher|oastify|interact\.sh|burpcollaborator",
                url,
                re.I,
            ):
                deny("fetches a webhook/paste/tunnel URL — a classic exfiltration endpoint")
            q = url.split("?", 1)[1] if "?" in url else ""
            if len(q) > 40 or re.search(r"https?://\d{1,3}(\.\d{1,3}){3}", url):
                _out(
                    "ask",
                    "WebFetch with data in the URL (long query string or raw IP) — a GET can exfiltrate as well as a POST. Check what is in the URL and approve.",
                )
            allow()
        if n == "webs earch".replace(" ", ""):
            allow()
        if n == "artifact":
            _out("ask", "The Artifact tool publishes a page other people can open. Approve only if you asked for it.")
        if re.search(r"(delete|trash|destroy|purge|remove|revoke)", n):
            _out("ask", f"Tool '{tool}' deletes/revokes something (irreversible). Approve to proceed.")
        if re.search(
            r"(send|share|publish|forward|invite|upload|post|comment|reply|notify|webhook|email|tweet|export|permission|move_to|push|navigate|goto|open_url|refund|charge|payout|transfer|invoice|payment|"
            r"create[_-]?(page|pages|item|items|draft|pull[_-]?request|issue|event|message|record|document|doc|file|gist|release)|"
            r"update[_-]?(page|item|record|event)|append|insert|write)",
            n,
        ):
            _out(
                "ask",
                f"Tool '{tool}' can SEND data out or make it visible to third parties. Check recipients/content and approve.",
            )
        allow()

    # ---- 2) Bash
    cmd = tin.get("command", "") or ""
    if len(cmd) > 16384:
        _out("ask", "Shell command exceeds the inspection limit; review it explicitly.")
    low = cmd.lower()
    try:
        command_tokens = shlex.split(cmd)
        normalized = " ".join(command_tokens)
    except ValueError:
        _out("ask", "Cannot parse this shell command safely; review it explicitly.")

    # 2a) DENY without asking — never legitimate in a normal session (deny beats everything)
    for p, why in (
        (
            r"--dangerously-skip-permissions|bypasspermissions|\"defaultmode\"\s*:\s*\"bypass",
            "tries to DISABLE Claude Code's permissions",
        ),
        (
            r"webhook\.site|hooks\.slack\.com|discord(app)?\.com/api/webhooks|ngrok\.(io|app|dev)|pastebin\.com|transfer\.sh|ntfy\.sh|api\.telegram\.org|requestbin|pipedream\.net|hookbin|burpcollaborator|interact\.sh|oastify\.com|ngrok-free\.app|ngrok\.app|trycloudflare\.com|loca\.lt|localtunnel|serveo\.net|0x0\.st|file\.io|catbox\.moe|termbin\.com|ix\.io|paste\.ee|hastebin|beeceptor|requestcatcher|webhook\.cool|bashupload|temp\.sh",
            "sends data to a webhook/paste service — a classic exfiltration channel",
        ),
        (
            r"\bbase64\b[^|]*\|\s*(curl|wget|nc|ncat)\b|\b(curl|wget)\b.*\$\(\s*base64",
            "encodes-and-sends data — an exfiltration pattern",
        ),
        (r"/dev/(tcp|udp)/|(^|[\s;&|/`(])(nc|ncat|socat|netcat)\s", "opens a raw network connection (netcat/socat)"),
        (r"(^|[\s;&|])(rm|shred|unlink)\s+(-\w*\s+)*\S*\.claude/(hooks|settings)", "deletes Claude's own defenses"),
    ):
        if re.search(p, low):
            deny(why + ". If this is truly intentional, run it yourself in a terminal.")

    # 2b) Email — sending only to yourself is fine; anything else asks
    if re.search(
        r"\bgws\b.*\bgmail\b.*(\+send|\+reply|\+reply-all|\+forward|\b(messages|drafts)\b.*\bsend\b)|\bsendmail\b|\bmail\s+-s\b|\bmutt\b.*\s-s\b|\bhimalaya\b.*\bsend\b|osascript.*(mail|send)",
        low,
    ):
        if not owner_send(cmd):
            asks.append("SENDS email — recipients or command scope need approval")

    # 2c) Sharing / publishing
    for p, why in (
        (
            r"\bgws\b.*\bdrive\b.*\bpermissions?\b.*\b(create|update|insert)\b|\bgws\b.*\bshare\b",
            "changes sharing permissions on a Drive file",
        ),
        (
            r"\bgws\b.*\bcalendar\b.*\b(insert|patch|update|import|quickadd)\b.*(sendupdates|attendees)",
            "creates/edits an event visible to other attendees",
        ),
        (
            r"\bgh\b\s+(gist\s+create|repo\s+create.*--public|release\s+(create|upload)|secret\s+set)",
            "publishes content on GitHub / changes secrets",
        ),
        (
            r"\bgh\b\s+(issue|pr)\s+(comment|create)|\bglab\b.*(comment|create)",
            "posts text on an issue/PR (visible to third parties)",
        ),
    ):
        if re.search(p, low):
            asks.append(why)

    # 2d) Network requests that carry local data, uploads, transfers, inline network scripts, DNS
    net_cmd = re.search(
        r"(^|[\s;&|(`/'\"])(curl|wget|https?|http|xh|aria2c|ssh|telnet|openssl\s+s_client)\s", normalized.lower()
    )
    net_cmd = net_cmd or any(
        os.path.basename(t) in {"curl", "wget", "http", "https", "xh", "aria2c", "ssh", "telnet"}
        for t in command_tokens
    )
    if net_cmd:
        if re.search(r"\s-(?:[a-zA-Z]*[FT])\S*|--(?:upload-file|form)(?:=|\s)", normalized):
            asks.append("uploads data using an attached form/file option")
        if re.search(
            r"\s-[a-z]*d[a-z]*[\s=@'\"]|--data|--form|\s-f[\s@'\"]|\s-t[\s@'\"]|--upload-file|--json|-x\s*['\"]?(post|put|patch)|--post-data|--post-file|--body-|\s(post|put|patch)\s",
            normalized.lower(),
        ):
            asks.append("POSTs/uploads data over the internet")
        if re.search(r"\$\(|`|\$\{?[a-z_][a-z0-9_]*|@[\w./~-]|<\s*[\w./~-]", normalized.lower()):
            asks.append("puts LOCAL data into a network request (command substitution, variable, @file or stdin)")
        if re.search(r"https?://\d{1,3}(\.\d{1,3}){3}", normalized.lower()):
            asks.append("talks to a raw IP address (no domain)")
    if re.search(
        r"(python3?|node|ruby|perl|php)\s+-[ce]\s|(python3?|node)\s+-\s*<<|\bdeno\s+eval", normalized.lower()
    ) and re.search(
        r"socket|http|urllib|request|fetch|net\.|connect|smtplib|ftplib|paramiko|boto3|requests|axios|websocket|dns",
        normalized.lower(),
    ):
        asks.append("runs an inline script with network capability")
    if re.search(
        r"(^|[\s;&|/])(scp|sftp)\s|\brsync\b.*\S+:|\brclone\s+(copy|sync|move|copyto)|\baws\s+s3\s+(cp|sync|mv)|\bgsutil\s+(cp|rsync)|\bgcloud\s+storage\s+cp|\baz\s+storage\s+blob\s+upload|\bb2\s+upload",
        normalized.lower(),
    ):
        asks.append("transfers files to another host/cloud")
    if re.search(r"(^|[\s;&|])(dig|nslookup|host)\s.*(\$\(|`|\$\{?[a-z_])", normalized.lower()):
        asks.append("builds a DNS query from local data (DNS exfiltration pattern)")

    if any(os.path.basename(t) in {"scp", "sftp"} for t in command_tokens):
        asks.append("transfers files to another host")
    if re.search(r"\bgh\b\s+api\b", " ".join(command_tokens).lower()) and re.search(
        r"--(?:method|field|raw-field|input)|\s-[XfF]", cmd
    ):
        asks.append("GitHub API request with an explicit method or payload")

    # 2d-bis) git operating on the ~/.claude baseline repo (evidence laundering)
    git_write = re.search(
        r"\bgit\b[^;|&]*\b(commit|add|rm|mv|reset|checkout|restore|stash|rebase|merge|cherry-pick|reflog|gc|prune|filter-branch|filter-repo|update-ref|push|pull|fetch|clean|tag|config|branch\s+-[dDmM])\b",
        low,
    )
    if git_write and (
        re.search(r"\bgit\b[^;|&]*\s-c\s+\S*\.claude(/|\b)", low)
        or re.search(r"\bcd\s+\S*\.claude(/|\b)", low)
        or cwd.replace("\\", "/").rstrip("/").endswith("/.claude")
    ):
        asks.append(
            "operates git on the ~/.claude BASELINE repository (commit/amend/reset there can launder a poisoned memory into a 'clean' baseline)"
        )
    # 2d-ter) download piped into an interpreter, and running a file that was written moments ago (two-step indirection)
    if re.search(
        r"\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b|\b(curl|wget)\b[^|]*\|\s*(python3?|node|perl|ruby)\b", low
    ):
        asks.append("pipes DOWNLOADED content into an interpreter (curl | sh — remote code execution)")
    m_run = re.search(
        r"(^|[\s;&|])(bash|sh|zsh|python3?|node|ruby|perl|php|source|\.)\s+([\w./~-]+\.(sh|py|js|rb|pl|php|bash|zsh))\b",
        cmd,
    )
    m_make = re.search(r"(^|[\s;&|])(make|npm\s+(run|test|start)|yarn\s+(run|test)|pnpm\s+(run|test))\b", low)
    for candidate in ([m_run.group(3)] if m_run else []) + (["Makefile", "package.json"] if m_make else []):
        p = os.path.expanduser(candidate)
        p = p if os.path.isabs(p) else os.path.join(cwd, p)
        try:
            if os.path.exists(p) and (time.time() - os.path.getmtime(p)) < 900:
                asks.append(
                    f"executes a file written in the last 15 minutes ({candidate}) — the two-step pattern used to hide a payload from the gate"
                )
                break
        except OSError:
            pass
    # 2e) Whitelisting only covers a single, fully understood push.
    if re.search(r"\bgit\b.*\bpush\b", low, re.S) and not trusted_push(cmd, cwd):
        asks.append("git push destination, options or command scope need approval")
    if re.search(r"\bgit\b\s+remote\s+(add|set-url)\b", low):
        asks.append("changes a git remote — verify its effective push URLs")

    # 2f) Secret reads (optional)
    if GATE_SECRET_READS and re.search(
        r"(cat|less|more|head|tail|grep|rg|sed|awk|open|cp|base64|xxd|od|strings|source|\.)\s[^|;&]*(\.env\b|\.pem\b|\.p12\b|\.key\b|id_rsa|id_ed25519|\.aws/credentials|\.netrc|\.npmrc|\.git-credentials)"
        r"|\$\(<\s*\S*\.env|dd\s+if=\S*\.(env|pem|key)|security\s+find-(generic|internet)-password|(^|[\s;&|])(env|printenv)\s*($|\||>)",
        low,
    ):
        asks.append("READS secrets/credentials — if the next step is to send something, that is a leak")

    if shell_protected_write(cmd, cwd, bool(git_write)):
        asks.append("WRITES to protected instructions, defenses or baseline via a canonical path")

    if GATE_SECRET_READS and canonical_secret_read(cmd, cwd):
        asks.append("READS secrets/credentials through a canonical file path")

    # 2g) Self-modification / machine persistence via the shell (any write verb or redirect aimed at a protected path)
    if PROTECTED_IN_CMD.search(low) and (
        re.search(r">>?\s*\S*", low)
        and re.search(
            r">>?\s*[^\s]*(\.claude|claude\.md|memory\.md|\.zshrc|\.bashrc|\.bash_profile|\.profile|\.gitconfig|\.ssh/|launchagents|systemd|\.cursor|\.vscode)",
            low,
        )
        or WRITE_VERBS.search(low)
    ):
        asks.append(
            "WRITES to a protected file (defenses/instructions/persistence) via the shell — an injection persists exactly this way"
        )
    if re.search(r"\bcd\s+[^;&|]*\.claude\b", low) and re.search(
        r"(>|(^|[\s;&|(`])(tee|mv|cp|ln|sed|perl|python3?|node|install|rsync|touch|chmod|rm)\b).*\b(hooks|agents|commands|skills|plugins|memory|rules|settings)\b",
        low,
    ):
        asks.append("WRITES inside ~/.claude after a cd (relative path to a protected folder)")
    for p, why in (
        (
            r"\bcrontab\b\s+(-e|-|\S+\.txt)|\blaunchctl\s+(load|bootstrap)|\bsystemctl\s+--user\s+(enable|start)",
            "installs a scheduled task (persistence)",
        ),
        (
            r"\bgit\s+config\b.*(core\.hookspath|init\.templatedir|include\.path)",
            "changes where git executes hooks (silent execution)",
        ),
        (
            r"\bnpm\s+(i|install)\b.*-g\b|\bpip3?\s+install\b|\bbrew\s+install\b|\bnpx\s+skills\b|\bclaude\s+(mcp\s+add|plugin\s+install)",
            "installs new software/plugin/MCP",
        ),
    ):
        if re.search(p, low):
            asks.append(why)

    # 2h) Destructive (non-rm)
    for p, why in (
        (r"\bgws\b.*\b(messages|threads)\b.*\b(delete|trash)\b|\bgws\b.*\bdelete\b", "deletes email/Google resources"),
        (r"\bgit\s+reset\s+--hard\b|\bgit\s+clean\s+-\w*f", "discards git changes"),
        (r"\b(gcloud|aws|az)\b.*\b(delete|rm|remove)\b", "deletes a cloud resource"),
        (r"\bmkfs\b|\bdd\b.*\sof=|>\s*/dev/(disk|sd|rdisk)|\bdiskutil\s+erase", "writes to / formats a disk"),
    ):
        if re.search(p, low):
            asks.append(why + " (irreversible)")

    # 2i) rm / delete family — asks unless confined to ephemeral temp dirs
    if re.search(r"(^|[\s;&|/])(rm|rmdir|shred|trash)(\s|$)", cmd) or re.search(r"\bfind\b.*\s-delete\b", cmd):
        if not temporary_delete(cmd, cwd):
            asks.append("DELETES files outside a proven temporary target")

    # ---- decision: deny already exited above; any ask wins over allow
    if asks:
        uniq = list(dict.fromkeys(asks))
        head = _CONFIG_ERROR + "This command " + uniq[0]
        more = (
            f" (+{len(uniq) - 1} more gate{'s' if len(uniq) > 2 else ''}: {'; '.join(uniq[1:])})"
            if len(uniq) > 1
            else ""
        )
        _out("ask", head + more + ". Approve only if you asked for exactly this.")
    allow()


try:
    main()
except SystemExit:
    raise
except Exception as e:
    _out(
        "ask",
        f"guard-irreversible CRASHED ({type(e).__name__}: {e}) — FAILING CLOSED. Approve consciously, or fix/disable the hook in settings.json.",
    )
