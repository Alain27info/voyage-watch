#!/usr/bin/env python3
"""
voyage-watch: alerts you on Telegram when https://www.voyage.benin.bj/ changes.

Two kinds of alerts:
  1. OPENING   - the "sera bientôt disponible" placeholder disappears or the site
                 redirects elsewhere (repeated up to MAX_ALERTS times).
  2. NEW CONTENT - the visible text or the links of the page change (e.g. new flight
                 dates), even if the placeholder phrase is still there, and even after
                 the site has opened. Confirmed over CONFIRM_CHECKS consecutive checks
                 to avoid false alarms. Disable with CONTENT_WATCH=0.

Standard library only, no pip install needed. Python 3.8+.

Usage:
  python3 monitor.py              # run forever, check every CHECK_INTERVAL seconds
  python3 monitor.py --once       # single check (for cron / GitHub Actions)
  python3 monitor.py --check      # single check, print result, send nothing
  python3 monitor.py --test       # send a test message to Telegram
  python3 monitor.py --chat-id    # print the chat IDs that messaged your bot
"""
import hashlib
import html
import json
import os
import re
import ssl
import subprocess
import sys
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

HERE = Path(__file__).resolve().parent


def load_env():
    """Read KEY=VALUE lines from .env next to the script (real env vars win)."""
    env_file = HERE / ".env"
    if not env_file.exists():
        return
    for line in env_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


load_env()

URL = os.environ.get("WATCH_URL", "https://www.voyage.benin.bj/")
# Text that is only present while the placeholder page is up (accent-insensitive).
MARKER = os.environ.get("PLACEHOLDER_MARKER", "sera bientot disponible")
INTERVAL = max(30, int(os.environ.get("CHECK_INTERVAL", "60")))  # never faster than 30s
TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
CHAT_IDS = [c.strip() for c in os.environ.get("TELEGRAM_CHAT_ID", "").split(",") if c.strip()]
STATE_FILE = Path(os.environ.get("STATE_FILE", str(HERE / "state.json")))
MAX_ALERTS = int(os.environ.get("MAX_ALERTS", "5"))            # repeats once the site opens
ERROR_THRESHOLD = int(os.environ.get("ERROR_THRESHOLD", "5"))  # consecutive failures before warning
HEARTBEAT_HOURS = float(os.environ.get("HEARTBEAT_HOURS", "24"))  # 0 disables
CONTENT_WATCH = os.environ.get("CONTENT_WATCH", "1") != "0"    # alert on any content change
CONFIRM_CHECKS = max(1, int(os.environ.get("CONFIRM_CHECKS", "2")))  # same new content N times in a row
# Phone ring via tg-ringer (userbot account, see `python -m tg_ringer.cli login`).
RING_TARGETS = [t.strip() for t in os.environ.get("RING_TARGETS", "").split(",") if t.strip()]
RING_SECONDS = int(os.environ.get("RING_SECONDS", "45"))
RING_ALERTS = int(os.environ.get("RING_ALERTS", "2"))          # ring only on the first N alerts of an opening
RING_MAX_PER_DAY = int(os.environ.get("RING_MAX_PER_DAY", "6"))  # hard cap per target (protects the account)
USER_AGENT = os.environ.get("USER_AGENT", "voyage-watch/1.1 (personal flight-opening alert)")


def log(msg):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), msg, flush=True)


def norm(text):
    """Lowercase and strip accents so 'Bientôt' == 'bientot'."""
    text = unicodedata.normalize("NFKD", text)
    return "".join(c for c in text if not unicodedata.combining(c)).lower()


# --------------------------------------------------------------------------- fetch

def _ssl_context():
    """Use certifi's CA bundle when installed (fixes 'certificate has expired' chain errors)."""
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return None


def fetch(url):
    req = urllib.request.Request(
        url, headers={"User-Agent": USER_AGENT, "Accept-Language": "fr-FR,fr;q=0.9,en;q=0.5"}
    )
    try:
        with urllib.request.urlopen(req, timeout=20, context=_ssl_context()) as resp:
            charset = resp.headers.get_content_charset() or "utf-8"
            body = resp.read(2_000_000).decode(charset, "replace")
            return {"status": resp.status, "final_url": resp.geturl(), "body": body, "error": None}
    except urllib.error.HTTPError as e:
        try:
            body = e.read(200_000).decode("utf-8", "replace")
        except Exception:
            body = ""
        return {"status": e.code, "final_url": url, "body": body, "error": f"HTTP {e.code}"}
    except Exception as e:  # DNS, timeout, TLS...
        return {"status": 0, "final_url": url, "body": "", "error": str(e)}


def _loc(u):
    p = urlparse(u)
    host = p.netloc.lower()
    host = host[4:] if host.startswith("www.") else host
    return host, p.path.rstrip("/")


def analyse(r, url=URL, marker=MARKER):
    """Return (label, detail). label: 'placeholder' | 'changed' | 'error'."""
    if r["error"] or r["status"] >= 400:
        return "error", r["error"] or f"HTTP {r['status']}"
    m = re.search(r"<title[^>]*>(.*?)</title>", r["body"], re.I | re.S)
    title = html.unescape(m.group(1)).strip() if m else ""
    if _loc(r["final_url"]) != _loc(url):
        return "changed", f"Redirection vers {r['final_url']}"
    if norm(marker) in norm(r["body"]):
        return "placeholder", title
    return "changed", title or "page modifiée"


# --------------------------------------------------------------------------- page content

_BLOCK = re.compile(
    r"</?(?:p|div|br|li|ul|ol|tr|td|th|table|section|article|header|footer|main|nav|"
    r"h[1-6]|form|button|label|option|dd|dt|hr)\b[^>]*>",
    re.I,
)


def page_lines(body):
    """Stable fingerprint material: title + visible text lines + link targets.

    Scripts, styles, comments, <head> metadata and hidden inputs are ignored, as are
    query strings in links, so tokens/nonces/cache-busters do not trigger alerts.
    """
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    lines = []
    if m:
        lines.append("Titre : " + html.unescape(m.group(1)))
    t = re.sub(r"<!--.*?-->", " ", body, flags=re.S)
    t = re.sub(r"<(script|style|noscript|template|svg|head)\b.*?</\1\s*>", " ", t, flags=re.S | re.I)
    links = set()
    for href in re.findall(r"""href\s*=\s*["']([^"']+)["']""", t, re.I):
        href = href.strip()
        if not href or href.startswith(("#", "javascript:")):
            continue
        links.add(href.split("#")[0].split("?")[0])
    t = _BLOCK.sub("\n", t)
    t = re.sub(r"<[^>]+>", " ", t)
    t = html.unescape(t)
    for line in t.split("\n"):
        line = re.sub(r"\s+", " ", line).strip()
        if line:
            lines.append(line)
    lines.extend("Lien : " + h for h in sorted(links))
    return lines


def fingerprint(lines):
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


def added_lines(old, new):
    seen = set(old)
    return [l for l in new if l not in seen]


# --------------------------------------------------------------------------- telegram

def tg(method, **params):
    data = urllib.parse.urlencode(params).encode()
    req = urllib.request.Request(f"https://api.telegram.org/bot{TOKEN}/{method}", data=data)
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.load(resp)


def notify(text):
    log(f"NOTIFY: {text}")
    if not TOKEN or not CHAT_IDS:
        log("(Telegram non configuré : définis TELEGRAM_BOT_TOKEN et TELEGRAM_CHAT_ID dans .env)")
        return
    for chat_id in CHAT_IDS:
        for attempt in range(3):
            try:
                tg("sendMessage", chat_id=chat_id, text=text[:4000], disable_web_page_preview="true")
                break
            except Exception as e:
                log(f"Telegram erreur (essai {attempt + 1}/3) : {e}")
                time.sleep(2)


def ring(state):
    """Make each RING_TARGETS phone ring (Telegram call via tg-ringer), within a daily cap."""
    now = time.time()
    rings = state.setdefault("rings", {})
    for target in RING_TARGETS:
        recent = [t for t in rings.get(target, []) if now - t < 86400]
        if len(recent) >= RING_MAX_PER_DAY:
            log(f"Appel {target} ignoré : plafond de {RING_MAX_PER_DAY}/24h atteint")
            rings[target] = recent
            continue
        try:
            res = subprocess.run(
                [sys.executable, "-m", "tg_ringer.cli", "call", target, "--seconds", str(RING_SECONDS)],
                capture_output=True, text=True, timeout=RING_SECONDS + 60,
            )
            out = (res.stdout + res.stderr).strip().splitlines()
            log(f"Appel {target} : code {res.returncode} | {out[-1] if out else ''}")
            if res.returncode == 0:
                recent.append(now)
        except Exception as e:
            log(f"Appel {target} échoué : {e}")
        rings[target] = recent


def print_chat_ids():
    if not TOKEN:
        sys.exit("Mets d'abord TELEGRAM_BOT_TOKEN dans .env")
    updates = tg("getUpdates").get("result", [])
    seen = {}
    for u in updates:
        msg = u.get("message") or u.get("channel_post") or {}
        chat = msg.get("chat", {})
        if "id" in chat:
            name = chat.get("first_name") or chat.get("title") or chat.get("username") or "?"
            seen[chat["id"]] = name
    if not seen:
        sys.exit("Aucun message trouvé. Envoie /start à ton bot dans Telegram, puis relance.")
    for cid, name in seen.items():
        print(f"chat_id = {cid}   ({name})")


# --------------------------------------------------------------------------- state / loop

def load_state():
    try:
        return json.loads(STATE_FILE.read_text())
    except Exception:
        return {"label": None, "alerts_sent": 0, "errors": 0, "last_heartbeat": time.time()}


def save_state(state):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state))


def adopt(state, fp, lines):
    """Make this page content the new reference."""
    state["fp"] = fp
    state["lines"] = lines[:300]
    state["pending_fp"] = None
    state["pending_n"] = 0


def content_message(label, old_lines, new_lines):
    added = added_lines(old_lines, new_lines)
    head = (
        "🆕 Le contenu du site a changé (la mention « bientôt disponible » est toujours là)."
        if label == "placeholder"
        else "🆕 Nouveau contenu sur le site."
    )
    if added:
        shown = [("• " + l[:160]) for l in added[:8]]
        more = f"\n(+ {len(added) - 8} autres lignes)" if len(added) > 8 else ""
        body = "Ajouté :\n" + "\n".join(shown) + more
    else:
        body = "Des éléments ont été retirés ou modifiés sur la page."
    return f"{head}\n{body}\n👉 {URL}"


def step(state):
    r = fetch(URL)
    label, detail = analyse(r)
    log(f"{label} | {detail}")

    if label == "error":
        state["errors"] += 1
        if state["errors"] == ERROR_THRESHOLD:
            notify(
                f"⚠️ {state['errors']} erreurs d'affilée sur {URL} ({detail}). "
                "Soit mon script est bloqué, soit le site est surchargé (peut-être une ouverture !). "
                "Vérifie vite à la main."
            )
        return

    if state["errors"] >= ERROR_THRESHOLD:
        notify("✅ Surveillance rétablie, le site répond de nouveau.")
    state["errors"] = 0

    previous = state.get("label")
    label_changed = previous is not None and label != previous

    if label == "placeholder":
        if previous is None:
            notify(f"👀 Surveillance démarrée. État actuel : page « bientôt disponible ». Contrôle toutes les {INTERVAL}s.")
        elif previous == "changed":
            notify("ℹ️ Le site est revenu à la page « bientôt disponible ».")
        state["alerts_sent"] = 0
    else:  # changed
        if state["alerts_sent"] < MAX_ALERTS:
            n = state["alerts_sent"] + 1
            notify(
                f"🚨 LA PAGE A CHANGÉ : les vols Paris-Cotonou ouvrent peut-être ! "
                f"({detail})\n👉 {URL}\n(alerte {n}/{MAX_ALERTS})"
            )
            state["alerts_sent"] = n
            if n <= RING_ALERTS:
                ring(state)

    if CONTENT_WATCH:
        lines = page_lines(r["body"])
        fp = fingerprint(lines)
        confirmed = state.get("fp")
        if confirmed is None or previous is None or label_changed:
            # first run, old state file, or an opening/closing already announced above
            adopt(state, fp, lines)
        elif fp != confirmed:
            if state.get("pending_fp") == fp:
                state["pending_n"] = state.get("pending_n", 0) + 1
            else:
                state["pending_fp"], state["pending_n"] = fp, 1
            log(f"contenu différent ({state['pending_n']}/{CONFIRM_CHECKS})")
            if state["pending_n"] >= CONFIRM_CHECKS:
                notify(content_message(label, state.get("lines", []), lines))
                ring(state)
                adopt(state, fp, lines)
        else:
            state["pending_fp"], state["pending_n"] = None, 0

    state["label"] = label


def heartbeat(state):
    if HEARTBEAT_HOURS <= 0:
        return
    if time.time() - state.get("last_heartbeat", 0) >= HEARTBEAT_HOURS * 3600:
        label = state.get("label")
        if label == "placeholder":
            status = "Le site affiche toujours « bientôt disponible »."
        elif label == "changed":
            status = "La page du site a changé : vérifie-la."
        else:
            status = "Pas encore de vérification réussie."
        notify(f"💚 Toujours actif. {status}")
        state["last_heartbeat"] = time.time()


def main():
    args = set(sys.argv[1:])
    if "--chat-id" in args:
        return print_chat_ids()
    if "--test" in args:
        return notify("✅ Test : le bot Telegram fonctionne.")
    if "--simulate" in args:
        # Same path as a real opening: Telegram message + phone ring. Doesn't touch the saved page state.
        state = load_state()
        notify(
            "🧪 SIMULATION (fausse alerte) : 🚨 LA PAGE A CHANGÉ : les vols Paris-Cotonou ouvrent "
            f"peut-être !\n👉 {URL}\n(ceci est un test)"
        )
        ring(state)
        save_state(state)
        return
    if "--check" in args:
        r = fetch(URL)
        label, detail = analyse(r)
        print(f"{label} | {detail}")
        if not r["error"]:
            print("--- contenu surveillé (aperçu) ---")
            for line in page_lines(r["body"])[:15]:
                print(" ", line[:120])
        return
    state = load_state()
    if "--once" in args:
        step(state)
        heartbeat(state)
        save_state(state)
        return
    log(f"Surveillance de {URL} toutes les {INTERVAL}s (Ctrl+C pour arrêter)")
    while True:
        try:
            step(state)
            heartbeat(state)
            save_state(state)
        except Exception as e:  # never let the loop die
            log(f"Erreur inattendue : {e}")
        time.sleep(INTERVAL)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
