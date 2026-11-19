#!/usr/bin/env python3
"""
guard-irreversible.py — AI Tripwire · Layer A (PreToolUse) · edição open-source Gauzzi & Co v1.1

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

# ------------------------------------------------------------------ CONFIG
OWNER_EMAILS = {"voce@suaempresa.com.br"}  # e-mail só para si mesmo passa sem perguntar
ALLOWED_GIT_REMOTES = re.compile(r"github\.com[:/](SUA-ORG|seu-usuario)/", re.I)  # push liberado; o resto pergunta
GATE_SECRET_READS = True  # perguntar quando um comando lê .env / chaves / keychain
# Files whose modification is self-modification or machine persistence (checked on the Edit/Write
# tools' file_path AND on the text of shell commands).
PROTECTED_PATHS = re.compile(
    r"/\.claude/(hooks|agents|commands|skills|plugins|memory|rules)/|/\.claude/projects/[^/]+/memory/|/\.claude/settings[^/]*\.json$|"
    r"/CLAUDE(\.local)?\.md$|/MEMORY\.md$|/\.claude\.json$|/\.mcp\.json$|/claude_desktop_config\.json$|"
    r"/\.(zshrc|zprofile|zshenv|bashrc|bash_profile|profile|gitconfig|npmrc|netrc)$|/\.ssh/|/\.aws/|"
    r"/Library/LaunchAgents/|/\.config/systemd/|/\.cursor/rules/|/\.cursorrules$|/AGENTS\.md$|/copilot-instructions\.md$|/\.vscode/(settings|mcp)\.json$|"
    r"/\.claude/fence-alarms\.log$|/\.claude/\.git/|/\.claude/tripwire\.json$|/\.claude/plugins/|/\.cursor/mcp\.json$|/\.codeium/|/\.windsurf/|/\.github/(instructions|prompts|agents|chatmodes)/|/\.git/hooks/",
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
    r"(^|[\s;&|(`])(mv|cp|tee|ln|install|rsync|truncate|touch|chmod|chown|chflags|dd|patch|unlink|shred|"
    r"sed\s+-[a-z]*i|perl\s+-[a-z]*i|python3?\s+-c|node\s+-e|ruby\s+-e|perl\s+-e|php\s+-r|"
    r"git\s+(checkout|restore|apply|stash)|chattr|curl\s.*\s-o\s|wget\s.*\s-O\s)",
    re.I,
)
_CONFIG_ERROR = ""

# Sobrescritas opcionais lidas de ~/.claude/tripwire.json (criado uma vez pelo install.sh; upgrades nunca o alteram):
#   {"owner_emails": ["you@x.com"], "allowed_git_remotes": "github\\.com[:/]YOUR-ORG/", "gate_secret_reads": true}
try:
    with open(os.path.expanduser("~/.claude/tripwire.json"), encoding="utf-8") as _cf:
        _cfg = json.load(_cf)
    if isinstance(_cfg.get("owner_emails"), list) and _cfg["owner_emails"]:
        OWNER_EMAILS = {str(e) for e in _cfg["owner_emails"]}
    if isinstance(_cfg.get("allowed_git_remotes"), str) and _cfg["allowed_git_remotes"]:
        ALLOWED_GIT_REMOTES = re.compile(_cfg["allowed_git_remotes"], re.I)
    if isinstance(_cfg.get("gate_secret_reads"), bool):
        GATE_SECRET_READS = _cfg["gate_secret_reads"]
except FileNotFoundError:
    pass
except (
    Exception
) as _e:  # um config quebrado não pode enfraquecer o portão em silêncio: mantém os padrões e avisa no primeiro ask
    _CONFIG_ERROR = f"(tripwire.json ilegível: {type(_e).__name__}; usando padrões embutidos) "
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
    _out("deny", "BLOQUEADO pelo Tripwire: " + reason)


def allow():
    sys.exit(0)


def git_remote_url(cwd, remote):
    try:
        return subprocess.run(
            ["git", "-C", cwd, "remote", "get-url", remote],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        ).stdout.strip()
    except Exception:
        return ""


def main():
    try:
        data = json.load(sys.stdin)
    except Exception:
        _out(
            "ask",
            "guard-irreversible não conseguiu ler a entrada — FALHANDO FECHADO. Aprove conscientemente ou conserte/desative o hook no settings.json.",
        )

    tool = data.get("tool_name", "") or ""
    tin = data.get("tool_input", {}) or {}
    cwd = data.get("cwd") or os.getcwd()
    asks = []  # every gate appends; the decision is made once, at the end

    # ---- 0) Edit/Write tools on protected files (defenses, instructions, machine persistence)
    if tool in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        path = (tin.get("file_path") or tin.get("notebook_path") or "").replace("\\", "/")
        if PROTECTED_PATHS.search(path):
            _out(
                "ask",
                "Isto modifica um arquivo PROTEGIDO (instruções / defesas / persistência da máquina): "
                + path
                + ". Uma injeção persiste exatamente assim. Aprove só se VOCÊ pediu esta edição.",
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
                deny("busca uma URL de webhook/colagem/túnel — endpoint clássico de exfiltração")
            q = url.split("?", 1)[1] if "?" in url else ""
            if len(q) > 40 or re.search(r"https?://\d{1,3}(\.\d{1,3}){3}", url):
                _out(
                    "ask",
                    "WebFetch com dados na URL (query longa ou IP cru) — um GET exfiltra tanto quanto um POST. Confira o que está na URL e aprove.",
                )
            allow()
        if n == "webs earch".replace(" ", ""):
            allow()
        if n == "artifact":
            _out(
                "ask",
                "A ferramenta Artifact publica uma página que outras pessoas podem abrir. Aprove só se foi você quem pediu.",
            )
        if re.search(r"(delete|trash|destroy|purge|remove|revoke)", n):
            _out("ask", f"Tool '{tool}' apaga/revoga algo (irreversível). Aprove para prosseguir.")
        if re.search(
            r"(send|share|publish|forward|invite|upload|post|comment|reply|notify|webhook|email|tweet|export|permission|move_to|push|navigate|goto|open_url|refund|charge|payout|transfer|invoice|payment|"
            r"create[_-]?(page|pages|item|items|draft|pull[_-]?request|issue|event|message|record|document|doc|file|gist|release)|"
            r"update[_-]?(page|item|record|event)|append|insert|write)",
            n,
        ):
            _out(
                "ask",
                f"Tool '{tool}' pode ENVIAR dados para fora ou torná-los visíveis a terceiros. Confira destinatários/conteúdo e aprove.",
            )
        allow()

    # ---- 2) Bash
    cmd = tin.get("command", "") or ""
    low = cmd.lower()

    # 2a) DENY without asking — never legitimate in a normal session (deny beats everything)
    for p, why in (
        (
            r"--dangerously-skip-permissions|bypasspermissions|\"defaultmode\"\s*:\s*\"bypass",
            "tenta DESLIGAR as permissões do Claude Code",
        ),
        (
            r"webhook\.site|hooks\.slack\.com|discord(app)?\.com/api/webhooks|ngrok\.(io|app|dev)|pastebin\.com|transfer\.sh|ntfy\.sh|api\.telegram\.org|requestbin|pipedream\.net|hookbin|burpcollaborator|interact\.sh|oastify\.com|ngrok-free\.app|ngrok\.app|trycloudflare\.com|loca\.lt|localtunnel|serveo\.net|0x0\.st|file\.io|catbox\.moe|termbin\.com|ix\.io|paste\.ee|hastebin|beeceptor|requestcatcher|webhook\.cool|bashupload|temp\.sh",
            "envia dados para um serviço de webhook/colagem — canal clássico de exfiltração",
        ),
        (
            r"\bbase64\b[^|]*\|\s*(curl|wget|nc|ncat)\b|\b(curl|wget)\b.*\$\(\s*base64",
            "codifica-e-envia dados — padrão de exfiltração",
        ),
        (r"/dev/(tcp|udp)/|(^|[\s;&|/`(])(nc|ncat|socat|netcat)\s", "abre conexão de rede crua (netcat/socat)"),
        (
            r"(^|[\s;&|])(rm|shred|unlink)\s+(-\w*\s+)*\S*\.claude/(hooks|settings)",
            "apaga as próprias defesas do Claude",
        ),
    ):
        if re.search(p, low):
            deny(why + ". Se for realmente intencional, rode você mesmo no terminal.")

    # 2b) Email — sending only to yourself is fine; anything else asks
    if re.search(
        r"\bgws\b.*\bgmail\b.*(\+send|\+reply|\+reply-all|\+forward|\b(messages|drafts)\b.*\bsend\b)|\bsendmail\b|\bmail\s+-s\b|\bmutt\b.*\s-s\b|\bhimalaya\b.*\bsend\b|osascript.*(mail|send)",
        low,
    ):
        flag_vals = re.findall(r"--(?:to|cc|bcc)[=\s]+([^\s]+)", low)
        rcpts = set()
        for v in flag_vals:
            rcpts |= set(re.findall(r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}", v))
        owners = {e.lower() for e in OWNER_EMAILS}
        if not (rcpts and rcpts <= owners):
            ext = sorted(r for r in rcpts if r.split("@")[1] not in {e.split("@")[1] for e in owners})
            asks.append(
                "ENVIA e-mail (irreversível)"
                + (f" para domínio EXTERNO: {', '.join(ext)}" if ext else "")
                + " — confira destinatários e anexos"
            )

    # 2c) Sharing / publishing
    for p, why in (
        (
            r"\bgws\b.*\bdrive\b.*\bpermissions?\b.*\b(create|update|insert)\b|\bgws\b.*\bshare\b",
            "altera permissões de compartilhamento de um arquivo no Drive",
        ),
        (
            r"\bgws\b.*\bcalendar\b.*\b(insert|patch|update|import|quickadd)\b.*(sendupdates|attendees)",
            "cria/edita evento visível a outros participantes",
        ),
        (
            r"\bgh\b\s+(gist\s+create|repo\s+create.*--public|release\s+(create|upload)|secret\s+set)",
            "publica conteúdo no GitHub / altera segredos",
        ),
        (
            r"\bgh\b\s+(issue|pr)\s+(comment|create)|\bglab\b.*(comment|create)",
            "posta texto em um issue/PR (visível a terceiros)",
        ),
    ):
        if re.search(p, low):
            asks.append(why)

    # 2d) Network requests that carry local data, uploads, transfers, inline network scripts, DNS
    net_cmd = re.search(r"(^|[\s;&|(`'\"])(curl|wget|https?|http|xh|aria2c|ssh|telnet|openssl\s+s_client)\s", low)
    if net_cmd:
        if re.search(
            r"\s-[a-z]*d[a-z]*[\s=@'\"]|--data|--form|\s-f[\s@'\"]|\s-t[\s@'\"]|--upload-file|--json|-x\s*['\"]?(post|put|patch)|--post-data|--post-file|--body-|\s(post|put|patch)\s",
            low,
        ):
            asks.append("faz POST/upload de dados pela internet")
        if re.search(r"\$\(|`|\$\{?[a-z_][a-z0-9_]*|@[\w./~-]|<\s*[\w./~-]", low):
            asks.append(
                "coloca dado LOCAL numa requisição de rede (substituição de comando, variável, @arquivo ou stdin)"
            )
        if re.search(r"https?://\d{1,3}(\.\d{1,3}){3}", low):
            asks.append("fala com um endereço IP cru (sem domínio)")
    if re.search(r"(python3?|node|ruby|perl|php)\s+-[ce]\s|(python3?|node)\s+-\s*<<|\bdeno\s+eval", low) and re.search(
        r"socket|http|urllib|request|fetch|net\.|connect|smtplib|ftplib|paramiko|boto3|requests|axios|websocket|dns",
        low,
    ):
        asks.append("roda um script inline com capacidade de rede")
    if re.search(
        r"(^|[\s;&|])(scp|sftp)\s|\brsync\b.*\S+@\S+:|\brclone\s+(copy|sync|move|copyto)|\baws\s+s3\s+(cp|sync|mv)|\bgsutil\s+(cp|rsync)|\bgcloud\s+storage\s+cp|\baz\s+storage\s+blob\s+upload|\bb2\s+upload",
        low,
    ):
        asks.append("transfere arquivos para outro host/nuvem")
    if re.search(r"(^|[\s;&|])(dig|nslookup|host)\s.*(\$\(|`|\$\{?[a-z_])", low):
        asks.append("monta uma consulta DNS com dado local (padrão de exfiltração por DNS)")

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
            "opera git no repositório BASELINE ~/.claude (commit/amend/reset ali pode lavar uma memória envenenada para uma baseline 'limpa')"
        )
    # 2d-ter) download piped into an interpreter, and running a file that was written moments ago (two-step indirection)
    if re.search(
        r"\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b|\b(curl|wget)\b[^|]*\|\s*(python3?|node|perl|ruby)\b", low
    ):
        asks.append("despeja conteúdo BAIXADO num interpretador (curl | sh — execução remota de código)")
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
                    f"executa um arquivo gravado nos últimos 15 minutos ({candidate}) — o padrão em dois passos usado para esconder um payload do portão"
                )
                break
        except OSError:
            pass
    # 2e) git push / remotes
    if re.search(r"\bgit\b.*\bpush\b", low):
        if re.search(r"--force\b|--force-with-lease\b|\s-f\b", low):
            asks.append("faz FORCE-PUSH (reescreve histórico)")
        try:
            toks = shlex.split(cmd)
        except Exception:
            toks = cmd.split()
        remote = "origin"
        if "push" in toks:
            after = [t for t in toks[toks.index("push") + 1 :] if not t.startswith("-")]
            if after:
                remote = after[0]
        url = remote if "://" in remote or "@" in remote else git_remote_url(cwd, remote)
        if not (url and ALLOWED_GIT_REMOTES.search(url)):
            asks.append(
                f"git push to remote '{remote}' ({url or 'url desconhecida'}) — fora da lista permitida; push para um remote estranho = exfiltração do repositório"
            )
    if re.search(r"\bgit\b\s+remote\s+(add|set-url)\b", low):
        asks.append("adiciona/altera um remote git — verifique a URL")

    # 2f) Secret reads (optional)
    if GATE_SECRET_READS and re.search(
        r"(cat|less|more|head|tail|grep|open|cp|base64|xxd|od|strings|source|\.)\s[^|;&]*(\.env\b|\.pem\b|\.p12\b|\.key\b|id_rsa|id_ed25519|\.aws/credentials|\.netrc|\.npmrc|\.git-credentials)"
        r"|\$\(<\s*\S*\.env|dd\s+if=\S*\.(env|pem|key)|security\s+find-(generic|internet)-password|(^|[\s;&|])(env|printenv)\s*($|\||>)",
        low,
    ):
        asks.append("LÊ segredos/credenciais — se o próximo passo for enviar algo, isso é vazamento")

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
            "ESCREVE em arquivo protegido (defesas/instruções/persistência) via shell — uma injeção persiste exatamente assim"
        )
    if re.search(r"\bcd\s+[^;&|]*\.claude\b", low) and re.search(
        r"(>|(^|[\s;&|(`])(tee|mv|cp|ln|sed|perl|python3?|node|install|rsync|touch|chmod|rm)\b).*\b(hooks|agents|commands|skills|plugins|memory|rules|settings)\b",
        low,
    ):
        asks.append("ESCREVE dentro de ~/.claude depois de um cd (caminho relativo para pasta protegida)")
    for p, why in (
        (
            r"\bcrontab\b\s+(-e|-|\S+\.txt)|\blaunchctl\s+(load|bootstrap)|\bsystemctl\s+--user\s+(enable|start)",
            "instala uma tarefa agendada (persistência)",
        ),
        (
            r"\bgit\s+config\b.*(core\.hookspath|init\.templatedir|include\.path)",
            "muda onde o git executa hooks (execução silenciosa)",
        ),
        (
            r"\bnpm\s+(i|install)\b.*-g\b|\bpip3?\s+install\b|\bbrew\s+install\b|\bnpx\s+skills\b|\bclaude\s+(mcp\s+add|plugin\s+install)",
            "instala software/plugin/MCP novo",
        ),
    ):
        if re.search(p, low):
            asks.append(why)

    # 2h) Destructive (non-rm)
    for p, why in (
        (
            r"\bgws\b.*\b(messages|threads)\b.*\b(delete|trash)\b|\bgws\b.*\bdelete\b",
            "apaga e-mails/recursos do Google",
        ),
        (r"\bgit\s+reset\s+--hard\b|\bgit\s+clean\s+-\w*f", "descarta alterações no git"),
        (r"\b(gcloud|aws|az)\b.*\b(delete|rm|remove)\b", "apaga recurso de nuvem"),
        (r"\bmkfs\b|\bdd\b.*\sof=|>\s*/dev/(disk|sd|rdisk)|\bdiskutil\s+erase", "escreve/formata disco"),
    ):
        if re.search(p, low):
            asks.append(why + " (irreversível)")

    # 2i) rm / delete family — asks unless confined to ephemeral temp dirs
    if re.search(r"(^|[\s;&|/])(rm|rmdir|shred|trash)(\s|$)", cmd) or re.search(r"\bfind\b.*\s-delete\b", cmd):
        ephemeral = ("/tmp/", "/private/tmp/", "/var/folders/", "/private/var/folders/", "scratchpad", "/dev/null")
        try:
            tokens = shlex.split(cmd)
        except Exception:
            tokens = []
        skip = {"rm", "rmdir", "shred", "trash", "find", "-delete", "&&", "||", ";", "|", "sudo"}
        paths = [t for t in tokens if not t.startswith("-") and t not in skip]
        if not (paths and all(any(e in p for e in ephemeral) for p in paths)):
            asks.append("APAGA arquivos (irreversível)")

    # ---- decision: deny already exited above; any ask wins over allow
    if asks:
        uniq = list(dict.fromkeys(asks))
        head = _CONFIG_ERROR + "Este comando " + uniq[0]
        more = (
            f" (+{len(uniq) - 1} {'portões' if len(uniq) > 2 else 'portão'} a mais: {'; '.join(uniq[1:])})"
            if len(uniq) > 1
            else ""
        )
        _out("ask", head + more + ". Aprove só se foi exatamente isso que você pediu.")
    allow()


# Claude Code writes the hook input as UTF-8 JSON. Python decodes a piped stdin with the locale
# encoding instead (cp1252 on most Windows installs), so non-ASCII text reached the gates as
# mojibake: a just-written script with an accented name was not recognised, and an accented path
# could turn a deny into an ask. A strict legacy decoder could not read such input at all. Read
# UTF-8 whatever the locale says; input that is not valid UTF-8 still fails closed in main().
try:
    sys.stdin.reconfigure(encoding="utf-8", errors="strict")
except Exception:  # no stdin, or not a text stream: main() fails closed on whatever it cannot read
    pass

try:
    main()
except SystemExit:
    raise
except Exception as e:
    _out(
        "ask",
        f"guard-irreversible QUEBROU ({type(e).__name__}: {e}) — FALHANDO FECHADO. Aprove conscientemente ou conserte/desative o hook no settings.json.",
    )
