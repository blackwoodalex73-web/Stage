"""Хранилище логов/статистики (SQLite) и разбор тела POST из Pawn (discord_logs.inc).

Формат тела:  key=<secret>&d=<urlencode(строки)>
Строки разделены \\n, поля в строке \\t:  категория \\t ник \\t текст (cp1251).
"""
from __future__ import annotations

import hmac
import json
import os
import re
import sqlite3
import threading
import time
from collections import Counter
from urllib.parse import unquote_to_bytes

# Категории логов, которые владелец может направлять в каналы. "stats" в каналы не рассылается.
CATEGORIES = [
    "admin", "adminchat", "adminreport", "join", "money", "donate", "vehicle",
    "inventory", "server", "casino", "report", "ask", "events", "alert", "sqlerror", "fsin",
]
RETENTION_DAYS = 30
ECONOMY_ALERT_RATIO = 1.20  # рост денег (руки+банк) за час больше 20% -> алерт
MAX_BODY = 64 * 1024


# ------------------------------------------------------------------ разбор запроса
def parse_body(body: bytes, secret: str):
    """Возвращает (ok, lines). ok=False - неверный секрет/формат. lines = [(category, nick, text)]."""
    key = None
    data = None
    for part in body.split(b"&"):
        name, _, value = part.partition(b"=")
        if name == b"key":
            key = unquote_to_bytes(value.replace(b"+", b" "))
        elif name == b"d":
            data = unquote_to_bytes(value.replace(b"+", b" "))
    if key is None or not hmac.compare_digest(key, secret.encode("utf-8")):
        return False, []
    if data is None:
        return True, []
    text = data.decode("cp1251", errors="replace")
    lines = []
    for raw in text.split("\n"):
        raw = raw.strip("\r")
        if not raw:
            continue
        fields = raw.split("\t", 2)
        if len(fields) < 3:
            continue
        cat, nick, msg = (f.strip() for f in fields)
        cat = re.sub(r"[^a-z0-9_]", "", cat.lower())[:20]
        if cat:
            lines.append((cat, nick[:32], msg[:400]))
    return True, lines


# ------------------------------------------------------------------ конфиг каналов
class ChannelConfig:
    def __init__(self, path: str):
        self.path = path
        self.data: dict[str, int] = {}
        self.load()

    def load(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                raw = json.load(f)
            self.data = {k: int(v) for k, v in raw.items() if str(v).isdigit()}
        except FileNotFoundError:
            self.data = {}
        except Exception:
            self.data = {}

    def save(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.data, f, ensure_ascii=False, indent=2)
        os.replace(tmp, self.path)

    def set(self, category: str, channel_id: int):
        self.data[category] = int(channel_id)
        self.save()

    def clear(self, category: str) -> bool:
        if category in self.data:
            del self.data[category]
            self.save()
            return True
        return False

    def channel_for(self, category: str):
        return self.data.get(category) or self.data.get("all")


# ------------------------------------------------------------------ SQLite
class Store:
    def __init__(self, path: str):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.lock = threading.Lock()
        with self.lock:
            self.db.executescript("""
                CREATE TABLE IF NOT EXISTS logs(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts INTEGER NOT NULL, category TEXT NOT NULL, nick TEXT NOT NULL, text TEXT NOT NULL,
                    sent INTEGER NOT NULL DEFAULT 0);
                CREATE INDEX IF NOT EXISTS ix_logs_ts ON logs(ts);
                CREATE INDEX IF NOT EXISTS ix_logs_cat ON logs(category, ts);
                CREATE INDEX IF NOT EXISTS ix_logs_sent ON logs(sent, id);
                CREATE TABLE IF NOT EXISTS stats(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts INTEGER NOT NULL, kind TEXT NOT NULL,
                    online INTEGER, money INTEGER, bank INTEGER, donate INTEGER, accounts INTEGER);
                CREATE INDEX IF NOT EXISTS ix_stats_kind ON stats(kind, ts);
            """)
            self.db.commit()

    # ---- запись
    def add_lines(self, lines, now: int | None = None) -> int:
        now = now or int(time.time())
        n = 0
        with self.lock:
            for cat, nick, text in lines:
                if cat == "stats":
                    self._add_stat(nick, text, now)
                    n += 1
                    continue
                self.db.execute("INSERT INTO logs(ts,category,nick,text,sent) VALUES (?,?,?,?,0)",
                                (now, cat, nick, text))
                n += 1
            self.db.commit()
        return n

    def _add_stat(self, nick: str, text: str, now: int):
        kv = dict(p.split("=", 1) for p in text.split(";") if "=" in p)

        def num(name):
            try:
                return int(kv.get(name, ""))
            except ValueError:
                return None

        if nick == "economy":
            prev = self.db.execute(
                "SELECT money,bank FROM stats WHERE kind='economy' ORDER BY ts DESC LIMIT 1").fetchone()
            self.db.execute("INSERT INTO stats(ts,kind,money,bank,donate,accounts) VALUES (?,?,?,?,?,?)",
                            (now, "economy", num("money"), num("bank"), num("donate"), num("accounts")))
            cur_total = (num("money") or 0) + (num("bank") or 0)
            if prev and prev[0] is not None and prev[1] is not None:
                prev_total = prev[0] + prev[1]
                if prev_total > 0 and cur_total > prev_total * ECONOMY_ALERT_RATIO:
                    growth = cur_total - prev_total
                    self.db.execute(
                        "INSERT INTO logs(ts,category,nick,text,sent) VALUES (?,?,?,?,0)",
                        (now, "alert", "economy",
                         f"Скачок денег за час: +{fmt_int(growth)} ({(cur_total / prev_total - 1) * 100:.0f}%). Проверьте на дюп."))
        elif "online" in kv:
            self.db.execute("INSERT INTO stats(ts,kind,online) VALUES (?,?,?)", (now, "online", num("online")))

    # ---- рассылка
    def pending(self, limit: int = 300):
        with self.lock:
            return self.db.execute(
                "SELECT id,ts,category,nick,text FROM logs WHERE sent=0 ORDER BY id LIMIT ?", (limit,)).fetchall()

    def mark_sent(self, ids):
        ids = list(ids)
        if not ids:
            return
        with self.lock:
            self.db.executemany("UPDATE logs SET sent=1 WHERE id=?", [(i,) for i in ids])
            self.db.commit()

    def prune(self, now: int | None = None) -> int:
        cutoff = (now or int(time.time())) - RETENTION_DAYS * 86400
        with self.lock:
            a = self.db.execute("DELETE FROM logs WHERE ts<?", (cutoff,)).rowcount
            b = self.db.execute("DELETE FROM stats WHERE ts<?", (cutoff,)).rowcount
            self.db.commit()
        return a + b

    # ---- поиск
    @staticmethod
    def _like(s: str) -> str:
        return "%" + s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"

    def search(self, nick: str, categories=None, days: int = 7, limit: int = 25):
        since = int(time.time()) - days * 86400
        sql = ("SELECT ts,category,nick,text FROM logs WHERE ts>=? AND "
               "(lower(nick)=lower(?) OR lower(text) LIKE lower(?) ESCAPE '\\')")
        args: list = [since, nick, self._like(nick)]
        if categories:
            sql += " AND category IN (%s)" % ",".join("?" * len(categories))
            args += list(categories)
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        with self.lock:
            return self.db.execute(sql, args).fetchall()

    # ---- статистика
    def online_by_day(self, days: int):
        since = int(time.time()) - days * 86400
        with self.lock:
            return self.db.execute(
                "SELECT date(ts,'unixepoch','localtime') d, AVG(online), MAX(online), COUNT(*) "
                "FROM stats WHERE kind='online' AND ts>=? GROUP BY d ORDER BY d", (since,)).fetchall()

    def economy_latest(self):
        """(последняя запись, запись ~сутки назад или самая ранняя) или (None, None)."""
        with self.lock:
            last = self.db.execute(
                "SELECT ts,money,bank,donate,accounts FROM stats WHERE kind='economy' ORDER BY ts DESC LIMIT 1").fetchone()
            if not last:
                return None, None
            prev = self.db.execute(
                "SELECT ts,money,bank,donate,accounts FROM stats WHERE kind='economy' AND ts<=? ORDER BY ts DESC LIMIT 1",
                (last[0] - 86400 + 600,)).fetchone()
            if not prev:
                prev = self.db.execute(
                    "SELECT ts,money,bank,donate,accounts FROM stats WHERE kind='economy' ORDER BY ts ASC LIMIT 1").fetchone()
            if prev and prev[0] == last[0]:
                prev = None
            return last, prev

    def admin_activity(self, days: int, category: str = "admin", top: int = 5):
        since = int(time.time()) - days * 86400
        with self.lock:
            return self.db.execute(
                "SELECT nick, COUNT(*) c FROM logs WHERE category=? AND ts>=? GROUP BY lower(nick) "
                "ORDER BY c DESC LIMIT ?", (category, since, top)).fetchall()

    def player_card(self, nick: str, days: int = 7):
        since = int(time.time()) - days * 86400
        with self.lock:
            last_join = self.db.execute(
                "SELECT ts,text FROM logs WHERE category='join' AND lower(nick)=lower(?) ORDER BY id DESC LIMIT 1",
                (nick,)).fetchone()
            by_cat = self.db.execute(
                "SELECT category, COUNT(*) FROM logs WHERE ts>=? AND (lower(nick)=lower(?) OR lower(text) LIKE lower(?) ESCAPE '\\') "
                "GROUP BY category ORDER BY 2 DESC", (since, nick, self._like(nick))).fetchall()
        recent = self.search(nick, None, days, 8)
        return last_join, by_cat, recent

    def online_series(self, hours: int = 24):
        since = int(time.time()) - hours * 3600
        with self.lock:
            return self.db.execute(
                "SELECT ts, online FROM stats WHERE kind='online' AND ts>=? ORDER BY ts", (since,)).fetchall()

    def economy_series(self, days: int = 7):
        since = int(time.time()) - days * 86400
        with self.lock:
            return self.db.execute(
                "SELECT ts, money, bank, donate, accounts FROM stats WHERE kind='economy' AND ts>=? ORDER BY ts",
                (since,)).fetchall()

    def complaints(self, days: int):
        since = int(time.time()) - days * 86400
        with self.lock:
            return [r[0] for r in self.db.execute(
                "SELECT text FROM logs WHERE category='report' AND ts>=?", (since,)).fetchall()]


# ------------------------------------------------------------------ категоризация жалоб
COMPLAINT_RULES = [
    ("Баг / ошибка", r"баг|глюк|ошибк|не работает|пропал|зависл|bug"),
    ("Читер", r"чит|cheat|hack|\bаим|aim|спидхак|валлхак|телепорт|летает|fly"),
    ("DM / убийство", r"\bдм\b|\bdm\b|deathmatch|убил|убивает|убивают|стреля"),
    ("TK / DB / SK", r"\bтк\b|\bдб\b|\bск\b|\bdb\b|\bsk\b|\btk\b|драйв|спавнкил"),
    ("Оскорбление / флуд", r"оскорб|\bоск\b|мать|родител|флуд|мат\b|нуб|тролл"),
    ("Мошенничество", r"обман|скам|кинул|кидает|мошен|развод"),
    ("Реклама", r"реклам|https?:|\.ru\b|\.com\b|discord\.gg"),
    ("Администрация", r"админ"),
]


def categorize_complaint(text: str) -> str:
    t = text.lower()
    for name, rx in COMPLAINT_RULES:
        if re.search(rx, t):
            return name
    return "Другое"


def top_complaints(texts, top_texts: int = 5):
    cats = Counter(categorize_complaint(t) for t in texts)
    norm = Counter(re.sub(r"\s+", " ", t.lower()).strip(" .!?") for t in texts)
    frequent = [(t, c) for t, c in norm.most_common(top_texts) if c >= 2]
    return cats.most_common(), frequent


# ------------------------------------------------------------------ форматирование
def fmt_int(n) -> str:
    return "-" if n is None else f"{n:,}".replace(",", " ")


def fmt_delta(n) -> str:
    return ("+" if n >= 0 else "-") + fmt_int(abs(n))


def fmt_line(ts: int, cat: str, nick: str, text: str, with_cat: bool = True) -> str:
    t = time.strftime("%d.%m %H:%M", time.localtime(ts))
    head = f"`{t}` [{cat}] " if with_cat else f"`{t}` "
    return f"{head}**{nick}**: {text}"


def chunk_lines(lines, limit: int = 1900):
    """Склеивает строки в сообщения не длиннее limit символов."""
    out, cur = [], ""
    for ln in lines:
        ln = ln[:limit]
        if cur and len(cur) + 1 + len(ln) > limit:
            out.append(cur)
            cur = ln
        else:
            cur = f"{cur}\n{ln}" if cur else ln
    if cur:
        out.append(cur)
    return out


def build_stats_text(store: Store, days: int) -> str:
    parts = [f"**Статистика за {days} дн.**", ""]
    rows = store.online_by_day(days)
    if rows:
        parts.append("**Онлайн по дням** (среднее / пик):")
        for d, avg, peak, _cnt in rows:
            parts.append(f"`{d}`  {avg:.1f} / {peak}")
    else:
        parts.append("Онлайн: данных пока нет.")
    parts.append("")
    last, prev = store.economy_latest()
    if last:
        t = time.strftime("%d.%m %H:%M", time.localtime(last[0]))
        parts.append(f"**Деньги в обороте** (на {t}):")
        parts.append(f"На руках: {fmt_int(last[1])}  |  В банках: {fmt_int(last[2])}")
        parts.append(f"Донат-валюта: {fmt_int(last[3])}  |  Аккаунтов: {fmt_int(last[4])}")
        if prev and last[1] is not None and prev[1] is not None:
            hours = max(1, round((last[0] - prev[0]) / 3600))
            total_now = (last[1] or 0) + (last[2] or 0)
            total_prev = (prev[1] or 0) + (prev[2] or 0)
            parts.append(f"Изменение (руки+банк) за {hours} ч: {fmt_delta(total_now - total_prev)}")
    else:
        parts.append("Экономика: данных пока нет (запись раз в час).")
    parts.append("")
    act = store.admin_activity(days, "admin")
    rep = store.admin_activity(days, "adminreport")
    if act or rep:
        parts.append("**Активность админов** (действий / ответов на репорты):")
        seen = {n.lower(): [n, c, 0] for n, c in act}
        for n, c in rep:
            seen.setdefault(n.lower(), [n, 0, 0])[2] = c
        for n, a, r in sorted(seen.values(), key=lambda x: -(x[1] + x[2]))[:5]:
            parts.append(f"{n}: {a} / {r}")
        parts.append("")
    texts = store.complaints(days)
    if texts:
        cats, frequent = top_complaints(texts)
        parts.append(f"**Жалобы** (всего {len(texts)}):")
        for name, cnt in cats[:8]:
            parts.append(f"{name}: {cnt}")
        if frequent:
            parts.append("Частые тексты:")
            for t, c in frequent:
                parts.append(f"{c}x «{t[:60]}»")
    else:
        parts.append("Жалоб за период нет.")
    return "\n".join(parts)


# ------------------------------------------------------------------ страница статистики
def _svg_bars(rows, width=640, height=180):
    """Столбики пик онлайна по дням + метка среднего."""
    import html as _h
    if not rows:
        return "<p class='muted'>Данных пока нет.</p>"
    peak_max = max(max(r[2] or 0, 1) for r in rows)
    n = len(rows)
    bw = (width - 40) / n
    parts = [f"<svg viewBox='0 0 {width} {height + 28}' class='chart' role='img' aria-label='Онлайн по дням'>"]
    for i, (d, avg, peak, _c) in enumerate(rows):
        x = 30 + i * bw
        hp = (peak or 0) / peak_max * height
        ha = (avg or 0) / peak_max * height
        parts.append(f"<rect x='{x + 3:.1f}' y='{height - hp:.1f}' width='{max(bw - 6, 2):.1f}' height='{hp:.1f}' class='bar'/>")
        parts.append(f"<rect x='{x + 3:.1f}' y='{height - ha:.1f}' width='{max(bw - 6, 2):.1f}' height='{ha:.1f}' class='bar2'/>")
        parts.append(f"<text x='{x + bw / 2:.1f}' y='{height + 14}' text-anchor='middle' class='lbl'>{_h.escape(d[5:])}</text>")
        parts.append(f"<text x='{x + bw / 2:.1f}' y='{height - hp - 3:.1f}' text-anchor='middle' class='lbl'>{peak}</text>")
    parts.append(f"<text x='2' y='10' class='lbl'>{peak_max}</text></svg>")
    return "".join(parts)


def _svg_line(points, width=640, height=140):
    """Линия онлайна за последние сутки."""
    if len(points) < 2:
        return "<p class='muted'>Данных пока нет.</p>"
    t0, t1 = points[0][0], points[-1][0]
    span = max(t1 - t0, 1)
    vmax = max(max(p[1] or 0 for p in points), 1)
    xs = [30 + (p[0] - t0) / span * (width - 40) for p in points]
    ys = [height - (p[1] or 0) / vmax * height for p in points]
    path = " ".join(f"{x:.1f},{y:.1f}" for x, y in zip(xs, ys))
    lab0 = time.strftime("%H:%M", time.localtime(t0))
    lab1 = time.strftime("%H:%M", time.localtime(t1))
    return (f"<svg viewBox='0 0 {width} {height + 20}' class='chart' role='img' aria-label='Онлайн за сутки'>"
            f"<polyline points='{path}' class='line'/>"
            f"<text x='2' y='10' class='lbl'>{vmax}</text>"
            f"<text x='30' y='{height + 14}' class='lbl'>{lab0}</text>"
            f"<text x='{width - 10}' y='{height + 14}' text-anchor='end' class='lbl'>{lab1}</text></svg>")


def render_stats_html(store: Store, days: int = 7, title: str = "Stage Role Play - статистика") -> str:
    import html as _h
    days = max(1, min(30, days))
    rows = store.online_by_day(days)
    series = store.online_series(24)
    last, prev = store.economy_latest()
    texts = store.complaints(days)
    cats, frequent = top_complaints(texts) if texts else ([], [])
    act = store.admin_activity(days, "admin")
    rep = store.admin_activity(days, "adminreport")

    eco = "<p class='muted'>Данных пока нет (запись раз в час).</p>"
    if last:
        delta = ""
        if prev and last[1] is not None and prev[1] is not None:
            d = ((last[1] or 0) + (last[2] or 0)) - ((prev[1] or 0) + (prev[2] or 0))
            hours = max(1, round((last[0] - prev[0]) / 3600))
            delta = f"<div class='card'><b>{_h.escape(fmt_delta(d))}</b><span>руки+банк за {hours} ч</span></div>"
        eco = ("<div class='cards'>"
               f"<div class='card'><b>{fmt_int(last[1])}</b><span>на руках</span></div>"
               f"<div class='card'><b>{fmt_int(last[2])}</b><span>в банках</span></div>"
               f"<div class='card'><b>{fmt_int(last[3])}</b><span>донат-валюта</span></div>"
               f"<div class='card'><b>{fmt_int(last[4])}</b><span>аккаунтов</span></div>{delta}</div>")

    comp = "<p class='muted'>Жалоб за период нет.</p>"
    if cats:
        comp = "<table>" + "".join(f"<tr><td>{_h.escape(n)}</td><td>{c}</td></tr>" for n, c in cats[:8]) + "</table>"
        if frequent:
            comp += "<p class='muted'>Частые тексты: " + "; ".join(f"{c}x «{_h.escape(t[:50])}»" for t, c in frequent) + "</p>"

    merged = {}
    for n, c in act:
        merged.setdefault(n.lower(), [n, 0, 0])[1] = c
    for n, c in rep:
        merged.setdefault(n.lower(), [n, 0, 0])[2] = c
    adm = "<p class='muted'>Данных пока нет.</p>"
    if merged:
        adm = ("<table><tr><th>Админ</th><th>Действий</th><th>Репортов</th></tr>" +
               "".join(f"<tr><td>{_h.escape(n)}</td><td>{a}</td><td>{r}</td></tr>"
                       for n, a, r in sorted(merged.values(), key=lambda x: -(x[1] + x[2]))[:10]) + "</table>")

    now = time.strftime("%d.%m.%Y %H:%M", time.localtime())
    return f"""<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>{_h.escape(title)}</title>
<style>
:root{{--bg:#f6f7f9;--fg:#1c1e21;--card:#fff;--muted:#6b7280;--acc:#2563eb;--acc2:#93c5fd;--line:#e5e7eb}}
@media (prefers-color-scheme:dark){{:root{{--bg:#111318;--fg:#e5e7eb;--card:#1a1d24;--muted:#9ca3af;--acc:#60a5fa;--acc2:#1e3a8a;--line:#2a2f3a}}}}
body{{margin:0;font:15px/1.5 system-ui,sans-serif;background:var(--bg);color:var(--fg)}}
main{{max-width:760px;margin:0 auto;padding:16px}} h1{{font-size:20px;margin:8px 0}} h2{{font-size:16px;margin:22px 0 8px}}
section{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px;margin:10px 0}}
.chart{{width:100%;height:auto}} .bar{{fill:var(--acc2)}} .bar2{{fill:var(--acc)}} .line{{fill:none;stroke:var(--acc);stroke-width:2}}
.lbl{{font-size:10px;fill:var(--muted)}} .muted{{color:var(--muted);font-size:13px}}
.cards{{display:flex;flex-wrap:wrap;gap:8px}} .card{{flex:1 1 130px;border:1px solid var(--line);border-radius:8px;padding:8px 10px}}
.card b{{display:block;font-size:17px}} .card span{{color:var(--muted);font-size:12px}}
table{{border-collapse:collapse;width:100%}} td,th{{border-bottom:1px solid var(--line);padding:5px 6px;text-align:left}}
</style></head><body><main>
<h1>{_h.escape(title)}</h1><p class="muted">Обновлено {now}. Период: {days} дн.</p>
<section><h2>Онлайн по дням (пик / среднее)</h2>{_svg_bars(rows)}</section>
<section><h2>Онлайн за последние 24 часа</h2>{_svg_line(series)}</section>
<section><h2>Деньги в обороте</h2>{eco}</section>
<section><h2>Жалобы игроков</h2>{comp}</section>
<section><h2>Активность админов</h2>{adm}</section>
</main></body></html>"""


# ------------------------------------------------------------------ HTTP-приёмник
def make_log_app(store: Store, secret: str, log=None, stats_key: str = ""):
    """aiohttp-приложение: POST /log (приём из Pawn), GET /stats и /stats.json (страница статистики)."""
    from aiohttp import web

    fails: dict[str, list[float]] = {}

    async def handle(request: "web.Request"):
        ip = request.remote or "?"
        now = time.time()
        recent = [t for t in fails.get(ip, []) if now - t < 60]
        if len(recent) >= 10:
            return web.Response(status=429, text="too many failures")
        if request.content_length is not None and request.content_length > MAX_BODY:
            return web.Response(status=413, text="too large")
        try:
            body = await request.read()
        except web.HTTPRequestEntityTooLarge:
            return web.Response(status=413, text="too large")
        ok, lines = parse_body(body, secret)
        if not ok:
            recent.append(now)
            fails[ip] = recent
            if log:
                log.warning("[logs] неверный секрет от %s", ip)
            return web.Response(status=403, text="forbidden")
        n = store.add_lines(lines)
        return web.Response(status=200, text=f"ok {n}")

    def stats_allowed(request: "web.Request") -> bool:
        if not stats_key:
            return True
        given = request.query.get("key", "")
        return hmac.compare_digest(given.encode("utf-8"), stats_key.encode("utf-8"))

    def days_param(request: "web.Request") -> int:
        try:
            return max(1, min(30, int(request.query.get("days", "7"))))
        except ValueError:
            return 7

    async def stats_page(request: "web.Request"):
        if not stats_allowed(request):
            return web.Response(status=403, text="forbidden")
        return web.Response(text=render_stats_html(store, days_param(request)), content_type="text/html", charset="utf-8")

    async def stats_json(request: "web.Request"):
        if not stats_allowed(request):
            return web.Response(status=403, text="forbidden")
        days = days_param(request)
        last, prev = store.economy_latest()
        cats, frequent = top_complaints(store.complaints(days))
        data = {
            "days": days,
            "online_by_day": [{"day": d, "avg": round(a or 0, 1), "peak": p} for d, a, p, _c in store.online_by_day(days)],
            "economy": ({"ts": last[0], "money": last[1], "bank": last[2], "donate": last[3], "accounts": last[4]} if last else None),
            "complaints": [{"category": n, "count": c} for n, c in cats],
        }
        return web.json_response(data)

    app = web.Application(client_max_size=MAX_BODY)
    app.router.add_post("/log", handle)
    app.router.add_get("/stats", stats_page)
    app.router.add_get("/stats.json", stats_json)
    return app
