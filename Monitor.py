#!/usr/bin/env python3
"""
voyage-watch: alerts you on Telegram when https://www.voyage.benin.bj/ stops
showing its "Bientôt disponible" placeholder (i.e. special flights open).

Standard library only, no pip install needed. Python 3.8+.

Usage:
  python3 monitor.py              # run forever, check every CHECK_INTERVAL seconds
  python3 monitor.py --once       # single check (for cron / GitHub Actions)
  python3 monitor.py --check      # single check, print result, send nothing
  python3 monitor.py --test       # send a test message to Telegram
  python3 monitor.py --chat-id    # print the chat IDs that messaged your bot
"""
import html
import json
import os
import re
import ssl
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

URL = os.environ.get("WATCH_URL", "https://voyage.benin.bj/")
# Text that is only present while the placeholder page is up (accent-insensitive).
MARKER = os.environ.get("PLACEHOLDER_MARKER", "sera bientot disponible")
INTERVAL = max(30, int(os.environ.get("CHECK_INTERVAL", "60")))  # never faster than 30s
TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
CHAT_IDS = [c.strip() for c in os.environ.get("TELEGRAM_CHAT_ID", "").split(",") if c.strip()]
STATE_FILE = Path(os.environ.get("STATE_FILE", str(HERE / "state.json")))
MAX_ALERTS = int(os.environ.get("MAX_ALERTS", "5"))            # repeats once the site changes
ERROR_THRESHOLD = int(os.environ.get("ERROR_THRESHOLD", "5"))  # consecutive failures before warning
HEARTBEAT_HOURS = float(os.environ.get("HEARTBEAT_HOURS", "24"))  # 0 disables
# Set to 1 if the site's TLS chain is broken/expired (only used for the page check, never Telegram).
INSECURE_SSL = os.environ.get("INSECURE_SSL", "0") == "1"
NOTIFY_EVERY_CHECK = os.environ.get("NOTIFY_EVERY_CHECK", "0") == "1"  # test mode: Telegram message on every check
USER_AGENT = os.environ.get("USER_AGENT", "voyage-watch/1.0 (personal flight-opening alert)")


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
        ctx = ssl._create_unverified_context() if INSECURE_SSL else _ssl_context()
        with urllib.request.urlopen(req, timeout=20, context=ctx) as resp:
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
                tg("sendMessage", chat_id=chat_id, text=text, disable_web_page_preview="true")
                break
            except Exception as e:
                log(f"Telegram erreur (essai {attempt + 1}/3) : {e}")
                time.sleep(2)


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
    STATE_FILE.write_text(json.dumps(state))


def step(state):
    r = fetch(URL)
    label, detail = analyse(r)
    log(f"{label} | {detail}")
    if NOTIFY_EVERY_CHECK:
        notify(f"🔎 Test : {label} | {detail}")

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
    state["label"] = label


def heartbeat(state):
    if HEARTBEAT_HOURS <= 0:
        return
    if time.time() - state.get("last_heartbeat", 0) >= HEARTBEAT_HOURS * 3600:
        notify(f"💚 Toujours actif. État actuel : {state.get('label')}.")
        state["last_heartbeat"] = time.time()


def main():
    args = set(sys.argv[1:])
    if "--chat-id" in args:
        return print_chat_ids()
    if "--test" in args:
        return notify("✅ Test : le bot Telegram fonctionne.")
    if "--check" in args:
        label, detail = analyse(fetch(URL))
        print(f"{label} | {detail}")
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