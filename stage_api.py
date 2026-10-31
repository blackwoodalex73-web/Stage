"""
Stage RP API: вход через Google и список персонажей для лаунчера. Discord для этого НЕ нужен.

  POST /google  key=<LOG_SECRET>&t=<Google ID token>  ->  "OK <sub> <email>" / "ERR ..."   (спрашивает игровой сервер)
  POST /chars   t=<Google ID token>                   ->  JSON слотов и персонажей           (спрашивает лаунчер)

Два способа запуска (выберите ОДИН, оба слушают один порт LOG_HTTP_PORT):
  * вместе с Discord-ботом (bot.py) - бот подключает эти же адреса сам;
  * без Discord:  python stage_api.py  (нужны только .env: LOG_SECRET, GOOGLE_CLIENT_IDS, при желании DB_*).
    Тогда POST /log (логи сервера в Discord) просто принимается и не сохраняется.
"""
import asyncio
import hmac
import logging
import os
import re
import time

BASE = os.path.dirname(os.path.abspath(__file__))
ACC_SLOTS, ACC_FREE_SLOTS = 5, 3


def _client_ids() -> set:
    return {x.strip() for x in os.getenv("GOOGLE_CLIENT_IDS", "").split(",") if x.strip()}


_greq = None


def _google_request():
    """One HTTP session for Google's keys (no new TLS connection on every sign-in)."""
    global _greq
    if _greq is None:
        import requests
        from google.auth.transport import requests as greq
        _greq = greq.Request(session=requests.Session())
    return _greq


def _verify_google(token: str) -> dict:
    from google.oauth2 import id_token
    # подпись Google и срок действия; 30 с запаса на расхождение часов (иначе "Token used too early")
    info = id_token.verify_oauth2_token(token, _google_request(), clock_skew_in_seconds=30)
    if info.get("aud") not in _client_ids():
        raise ValueError(f"audience: the token is for {info.get('aud')}, GOOGLE_CLIENT_IDS has other IDs")
    if info.get("iss") not in ("accounts.google.com", "https://accounts.google.com"):
        raise ValueError("issuer")
    if not str(info.get("sub", "")).isdigit():
        raise ValueError("sub")
    return info


def _short(e) -> str:
    """The reason for the game server's log: one line, latin (the SA-MP console is not UTF-8), at most 120 chars."""
    t = re.sub(r"[^\x20-\x7e]", "?", str(e) or type(e).__name__)
    return re.sub(r"\s+", " ", t)[:120]


def _db_config() -> dict:
    cfg = {"host": os.getenv("DB_HOST", "").strip(), "user": os.getenv("DB_USER", "").strip(),
           "password": os.getenv("DB_PASS", ""), "database": os.getenv("DB_NAME", "").strip()}
    if cfg["host"] and cfg["user"] and cfg["database"]:
        return cfg
    path = os.getenv("STAGE_MYSQL_CFG", "").strip() or os.path.join(BASE, "..", "scriptfiles", "stage_mysql.cfg")
    try:
        with open(path, encoding="cp1251", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                key = {"host": "host", "user": "user", "pass": "password", "password": "password", "db": "database",
                       "database": "database"}.get(k.strip().lower())
                if key and not cfg[key]:
                    cfg[key] = v.strip()
    except OSError:
        pass
    return cfg


def _load_chars(sub: str) -> dict:
    import pymysql
    c = _db_config()
    if not (c["host"] and c["user"] and c["database"]):
        raise RuntimeError("нет настроек базы (DB_* в .env или scriptfiles/stage_mysql.cfg)")
    con = pymysql.connect(host=c["host"], user=c["user"], password=c["password"], database=c["database"],
                          charset="utf8", connect_timeout=5, read_timeout=5, autocommit=True)
    try:
        with con.cursor() as cur:
            cur.execute("SELECT a.`id` FROM `stage_google_links` g JOIN `stage_accounts` a ON a.`id` = g.`account_id` "
                        "WHERE g.`sub` = %s LIMIT 1", (sub,))
            row = cur.fetchone()
            if not row:      # первый вход: аккаунт создаст сервер, когда игрок зайдёт в игру
                return {"ok": True, "slots": ACC_FREE_SLOTS, "chars": []}
            acc = int(row[0])
            slots = ACC_FREE_SLOTS
            cur.execute("SELECT `slots` FROM `stage_account_slots` WHERE `account_id` = %s LIMIT 1", (acc,))
            r = cur.fetchone()
            if r and r[0]:
                slots = max(ACC_FREE_SLOTS, min(ACC_SLOTS, int(r[0])))
            cur.execute("SELECT c.`slot`, c.`nickname`, IFNULL(a.`level`, 0), IFNULL(a.`sex`, 0), IFNULL(a.`money`, 0) "
                        "FROM `stage_characters` c LEFT JOIN `accounts` a ON a.`nickname` = c.`nickname` "
                        "WHERE c.`account_id` = %s ORDER BY c.`slot`", (acc,))
            chars, seen = [], set()
            for slot, nick, level, sex, money in cur.fetchall():
                slot = int(slot)
                if not (0 <= slot < ACC_SLOTS) or slot in seen:
                    continue
                seen.add(slot)
                chars.append({"slot": slot, "nick": str(nick), "level": int(level or 0),
                              "sex": int(sex) if int(sex or 0) in (1, 2) else 0, "money": int(money or 0)})
            return {"ok": True, "slots": slots, "chars": chars}
    finally:
        con.close()


def add_routes(app, secret: str, log: logging.Logger):
    """POST /google и POST /chars в aiohttp-приложение (бот или отдельный запуск)."""
    from aiohttp import web
    hits: dict = {}

    async def google_verify(request):
        t0 = time.monotonic()
        ip = request.remote or "?"
        data = await request.post()
        if not data:
            # SA-MP шлёт форму; пустое тело = запрос дошёл, но без данных (не тот Content-Type / обрезан прокси)
            log.warning("[google] %s: пустое тело запроса (Content-Type: %s)", ip, request.headers.get("Content-Type", "-"))
            return web.Response(text="ERR empty body", status=400)
        if not secret or not hmac.compare_digest(str(data.get("key", "")), secret):
            log.warning("[google] %s: неверный ключ (log_secret в stage_discord.cfg не равен LOG_SECRET)", ip)
            return web.Response(text="ERR key: log_secret != LOG_SECRET", status=403)
        if not _client_ids():
            log.error("[google] GOOGLE_CLIENT_IDS пуст")
            return web.Response(text="ERR GOOGLE_CLIENT_IDS is empty")
        token = str(data.get("t", ""))
        if token == "ping":                                 # проверка связи при старте игрового сервера (v38)
            log.info("[google] %s: проверка связи от игрового сервера - ключ верный", ip)
            return web.Response(text=f"PONG ids={len(_client_ids())}")
        if not (100 <= len(token) <= 4000):
            log.warning("[google] %s: токен неверной длины (%d)", ip, len(token))
            return web.Response(text=f"ERR token length {len(token)}")
        try:
            info = await asyncio.get_running_loop().run_in_executor(None, _verify_google, token)
        except Exception as e:
            log.warning("[google] %s: отклонено за %d мс: %s", ip, (time.monotonic() - t0) * 1000, e)
            return web.Response(text=f"ERR invalid: {_short(e)}")
        email = (info.get("email") or "-").replace(" ", "")
        log.info("[google] %s: вход %s за %d мс", ip, email, (time.monotonic() - t0) * 1000)
        return web.Response(text=f"OK {info['sub']} {email}")

    async def chars_api(request):
        ip = request.remote or "?"
        now = time.time()
        recent = [t for t in hits.get(ip, []) if now - t < 60]
        if len(recent) >= 20:                               # 20 запросов в минуту с адреса
            return web.json_response({"ok": False, "error": "too many requests"}, status=429)
        recent.append(now)
        hits[ip] = recent
        if not _client_ids():
            return web.json_response({"ok": False, "error": "GOOGLE_CLIENT_IDS is empty in .env"}, status=503)
        data = await request.post()
        token = str(data.get("t", ""))
        if not (100 <= len(token) <= 4000):
            return web.json_response({"ok": False, "error": "token"}, status=400)
        loop = asyncio.get_running_loop()
        try:
            info = await loop.run_in_executor(None, _verify_google, token)
        except Exception as e:
            log.info("[chars] токен отклонён: %s", e)
            return web.json_response({"ok": False, "error": "google"}, status=401)
        try:
            out = await loop.run_in_executor(None, _load_chars, str(info["sub"]))
        except Exception as e:
            log.warning("[chars] база недоступна: %s", e)
            return web.json_response({"ok": False, "error": "database"}, status=503)
        log.info("[chars] %s: персонажей %d", info.get("email", "-"), len(out["chars"]))
        return web.json_response(out)

    app.router.add_post("/google", google_verify)
    app.router.add_post("/chars", chars_api)


def main():
    from aiohttp import web
    try:
        from dotenv import load_dotenv
        load_dotenv(os.path.join(BASE, ".env"))
    except ImportError:
        pass
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    log = logging.getLogger("stage-api")
    secret = os.getenv("LOG_SECRET", "").strip()
    host = os.getenv("LOG_HTTP_HOST", "0.0.0.0").strip()
    # Railway / хостинги дают порт в PORT; LOG_HTTP_PORT, если задан, важнее (на него настроен TCP Proxy)
    port = int(os.getenv("LOG_HTTP_PORT", "").strip() or os.getenv("PORT", "").strip() or "8099")
    if len(secret) < 12:
        log.error("[config] LOG_SECRET не задан или короче 12 символов (тот же, что log_secret в scriptfiles/stage_discord.cfg)")
        raise SystemExit(1)
    if not _client_ids():
        log.error("[config] GOOGLE_CLIENT_IDS пуст: впишите Web Client ID (тот же, что GOOGLE_WEB_CLIENT_ID лаунчера)")
        raise SystemExit(1)
    app = web.Application(client_max_size=64 * 1024)
    add_routes(app, secret, log)
    seen = {"log": 0.0}

    async def log_sink(request):                            # логи сервера: без Discord их некуда отправлять
        now = time.time()
        if now - seen["log"] > 600:                         # раз в 10 минут: видно, что игровой сервер достучался
            seen["log"] = now
            log.info("[log] логи игрового сервера приходят (%s) - связь сервер -> API есть", request.remote or "?")
        return web.Response(text="OK")

    async def health(request):
        return web.Response(text=f"Stage API v38 works: client ids {len(_client_ids())}, port {port}")

    app.router.add_post("/log", log_sink)
    app.router.add_get("/", health)
    cfg = _db_config()
    log.info("[config] LOG_SECRET: %d символов, GOOGLE_CLIENT_IDS: %s, база для /chars: %s", len(secret),
             ", ".join(sorted(x[:12] + "..." for x in _client_ids())), cfg["host"] or "не задана")
    if os.getenv("RAILWAY_ENVIRONMENT") or os.getenv("RAILWAY_PROJECT_ID"):
        log.info("[config] Railway: TCP Proxy должен вести на порт %d; в stage_discord.cfg log_url=<адрес TCP Proxy>/log "
                 "(без https://)", port)
    # 0.0.0.0 -> все адреса, и IPv4, и IPv6 (прокси хостинга может прийти по любому)
    bind = None if host in ("", "0.0.0.0", "::", "*") else host
    log.info("[api] без Discord: %s:%d  (/google для сервера, /chars для лаунчера)", bind or "*", port)
    web.run_app(app, host=bind, port=port, print=None)


if __name__ == "__main__":
    main()
