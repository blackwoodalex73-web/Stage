"""Stage Role Play | 01 - Discord бот управления сервером (SA-MP).

Возможности
  /status                  - состояние сервера (онлайн/офлайн, игроки, пинг)   [все]
  /online                  - список игроков онлайн                              [все]
  /srv <команда>           - админ-команда на игровой сервер (help - список)   [админы бота]
  /say <текст>             - сообщение всем игрокам                             [админы бота]
  /admins                  - администраторы онлайн и в базе                     [админы бота]
  /setadmin <ник> <1-6>    - назначить игрового администратора                  [ТОЛЬКО владелец]
  /removeadmin <ник>       - снять игрового администратора                      [ТОЛЬКО владелец]
  /setlogchannel, /clearlogchannel, /logchannels - каналы для логов сервера       [ТОЛЬКО владелец]
  /adminlog <ник> [дней]   - журнал действий админа                             [админы бота]
  /searchlog <ник> [категория] [дней] - поиск в логах                           [админы бота]
  /stats [дней]            - онлайн по дням, деньги в обороте, топ жалоб, активность админов [админы бота]
  /player <ник> [дней]     - карточка игрока по логам                           [админы бота]

Личные сообщения боту (как команды в игре, со слешем):
  /ban 5 3 причина, /kick 5 причина, /givemoney 5 1000 ... - любые команды, которые понимает /srv  [админы бота]
  /status, /online, /link <код>, /myaccounts, /help                                               [все]

Статус сервера определяется через query-протокол SA-MP (UDP), пароль RCON для него не нужен.
Бот сам меняет свой статус в Discord (кто в сети / сервер выключен) и, если указан
STATUS_CHANNEL_ID, ведёт в канале одно обновляемое сообщение со статусом.

Безопасность
  * OWNER_DISCORD_ID (файл .env) - единственный, кто может назначать/снимать админов.
  * ADMIN_DISCORD_IDS - остальные, кто может пользоваться /srv, /say, /admins.
  * Игровой сервер проверяет Discord ID ещё раз (scriptfiles/stage_discord.cfg: owner= / admin=).
"""
import asyncio
import json
import logging
import os
import re
import sys
import time

import discord
discord.VoiceClient.warn_nacl = False  # голос не используется
from discord import app_commands
from discord.ext import tasks
from dotenv import load_dotenv

import query
import logstore
from rcon import rcon

load_dotenv()
log = logging.getLogger("stage-bot")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

BASE = os.path.dirname(os.path.abspath(__file__))
STATE_FILE = os.path.join(BASE, "status_message.json")
CONFIG_FILE = os.path.join(BASE, "bot_config.json")
DB_FILE = os.path.join(BASE, "botdata.sqlite")


def fatal(msg: str):
    log.error("[config] %s", msg)
    sys.exit(1)


def _ids(raw: str) -> set[str]:
    return {x.strip() for x in raw.split(",") if x.strip()}


TOKEN = os.getenv("DISCORD_TOKEN", "")
RCON_PASSWORD = os.getenv("SAMP_RCON_PASSWORD", "")
HOST = os.getenv("SAMP_HOST", "127.0.0.1")
PORT = int(os.getenv("SAMP_PORT", "7777"))
FALLBACK_PORTS = [int(p) for p in os.getenv("SAMP_FALLBACK_PORTS", "7777").replace(" ", "").split(",") if p]
GUILD_ID = os.getenv("DISCORD_GUILD_ID", "").strip()
OWNER = os.getenv("OWNER_DISCORD_ID", "").strip()
ADMINS = _ids(os.getenv("ADMIN_DISCORD_IDS", "")) | ({OWNER} if OWNER else set())
STATUS_CHANNEL_ID = os.getenv("STATUS_CHANNEL_ID", "").strip()
REFRESH = max(15, int(os.getenv("STATUS_REFRESH", "30")))
LOG_SECRET = os.getenv("LOG_SECRET", "").strip()
LOG_HTTP_HOST = os.getenv("LOG_HTTP_HOST", "0.0.0.0").strip()
LOG_HTTP_PORT = int(os.getenv("LOG_HTTP_PORT", "8099"))
STATS_PAGE_KEY = os.getenv("STATS_PAGE_KEY", "").strip()

if not TOKEN or TOKEN.startswith("put_"):
    fatal("DISCORD_TOKEN не задан")
if not re.fullmatch(r"\d{17,20}", OWNER):
    fatal("OWNER_DISCORD_ID не задан или неверный (нужен числовой Discord ID владельца)")
for _id in ADMINS:
    if not re.fullmatch(r"\d{17,20}", _id):
        fatal(f"Неверный Discord ID в ADMIN_DISCORD_IDS: {_id}")
if not RCON_PASSWORD:
    log.warning("[config] SAMP_RCON_PASSWORD не задан: /status и /online работают, команды управления - нет")
elif len(RCON_PASSWORD) < 12 or RCON_PASSWORD.lower() in {"5656", "changeme", "1234", "123456"}:
    log.warning("[config] слабый RCON-пароль! Любой, кто его узнает, получит полный контроль над сервером. "
                "Задайте длинный случайный пароль (одинаковый в server.cfg и в .env).")

FORBIDDEN = re.compile(r"['\"`\\%;{}\r\n\x00]")  # то же правило, что и на стороне Pawn
NICK_RE = re.compile(r"[A-Za-z0-9_.\[\]()$@=]{3,24}")
MAX_LEN = 200

# ---------------------------------------------------------------- состояние сервера
active_port = PORT
last_info: "query.ServerInfo | None" = None
last_error = ""
last_ok = 0.0


async def probe_info() -> "query.ServerInfo | None":
    """Опрашивает сервер: сначала запомненный порт, затем остальные (SAMP_PORT, SAMP_FALLBACK_PORTS)."""
    global active_port, last_info, last_error, last_ok
    order = [active_port] + [p for p in [PORT] + FALLBACK_PORTS if p != active_port]
    errors = []
    for port in order:
        try:
            info = await query.query_info(HOST, port)
        except Exception as e:  # таймаут / сеть
            errors.append(f"{port}: {type(e).__name__}")
            continue
        if port != active_port:
            log.info("[query] сервер отвечает на порту %d (в .env был %d)", port, active_port)
        active_port = port
        last_info, last_ok, last_error = info, time.time(), ""
        return info
    last_info = None
    last_error = f"нет ответа от {HOST} (порты: {', '.join(errors)})"
    return None


def status_embed(info: "query.ServerInfo | None", players: "list[query.Player] | None" = None) -> discord.Embed:
    if info is None:
        e = discord.Embed(title="Stage Role Play | 01", description="🔴 **Сервер недоступен**", colour=0xE74C3C)
        e.add_field(name="Диагностика", value=last_error or "нет данных", inline=False)
        e.set_footer(text="Если сервер на самом деле включён: проверьте SAMP_HOST/SAMP_PORT в .env, "
                          "`query 1` в server.cfg и открыт ли UDP-порт.")
    else:
        e = discord.Embed(title=info.hostname or "Stage Role Play | 01", description="🟢 **Сервер онлайн**", colour=0x2ECC71)
        e.add_field(name="Игроки", value=f"{info.players}/{info.max_players}", inline=True)
        e.add_field(name="Пинг до бота", value=f"{info.ping_ms} мс", inline=True)
        e.add_field(name="Адрес", value=f"`{HOST}:{info.port}`", inline=True)
        e.add_field(name="Режим", value=info.gamemode or "-", inline=True)
        e.add_field(name="Язык", value=info.language or "-", inline=True)
        e.add_field(name="Пароль", value="есть" if info.password else "нет", inline=True)
        if players:
            top = "\n".join(f"`{p.pid:>3}` {p.name}" for p in players[:15])
            e.add_field(name=f"Игроки онлайн ({len(players)})", value=top[:1000], inline=False)
    e.timestamp = discord.utils.utcnow()
    return e


# ---------------------------------------------------------------- бот
intents = discord.Intents.none()
intents.guilds = True
intents.dm_messages = True     # команды в личке бота; текст сообщений в личке приходит и без Message Content


class Bot(discord.Client):
    def __init__(self):
        super().__init__(intents=intents)
        self.tree = app_commands.CommandTree(self)

    async def setup_hook(self):
        if GUILD_ID:
            guild = discord.Object(id=int(GUILD_ID))
            self.tree.copy_global_to(guild=guild)
            await self.tree.sync(guild=guild)
        else:
            await self.tree.sync()
        refresh_status.start()
        await start_log_services()

    async def on_ready(self):
        log.info("вошёл как %s, админов бота: %d, владелец: %s", self.user, len(ADMINS), OWNER)

    async def on_message(self, message: discord.Message):
        if message.author.bot or message.guild is not None:
            return                         # только личные сообщения боту
        try:
            await handle_dm(message)
        except Exception as e:
            log.error("[dm] %s: %s", message.author.id, e)
            await message.channel.send(f"Ошибка: {e}")


bot = Bot()


@tasks.loop(seconds=REFRESH)
async def refresh_status():
    info = await probe_info()
    try:
        if info:
            await bot.change_presence(status=discord.Status.online,
                                      activity=discord.Game(f"Онлайн: {info.players}/{info.max_players}"))
        else:
            await bot.change_presence(status=discord.Status.dnd, activity=discord.Game("Сервер выключен"))
    except Exception as e:
        log.warning("[presence] %s", e)
    if STATUS_CHANNEL_ID:
        await update_status_message(info)


@refresh_status.before_loop
async def _wait_ready():
    await bot.wait_until_ready()


async def update_status_message(info):
    players = None
    if info and info.players:
        try:
            players = await query.query_players(HOST, active_port)
        except Exception:
            players = None
    embed = status_embed(info, players)
    try:
        channel = bot.get_channel(int(STATUS_CHANNEL_ID)) or await bot.fetch_channel(int(STATUS_CHANNEL_ID))
        msg_id = None
        if os.path.exists(STATE_FILE):
            with open(STATE_FILE, encoding="utf-8") as f:
                data = json.load(f)
            if str(data.get("channel")) == STATUS_CHANNEL_ID:
                msg_id = data.get("message")
        if msg_id:
            try:
                msg = await channel.fetch_message(int(msg_id))
                await msg.edit(embed=embed)
                return
            except discord.NotFound:
                pass
        msg = await channel.send(embed=embed)
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump({"channel": STATUS_CHANNEL_ID, "message": msg.id}, f)
    except Exception as e:
        log.warning("[status-message] %s", e)


# ---------------------------------------------------------------- доступ и отправка на сервер
def is_owner(inter: discord.Interaction) -> bool:
    return str(inter.user.id) == OWNER


def is_admin(inter: discord.Interaction) -> bool:
    return str(inter.user.id) in ADMINS


async def send_to_server(discord_id: int, text: str) -> str:
    if not RCON_PASSWORD:
        return "RCON-пароль не задан в .env"
    ports = [active_port] + [p for p in [PORT] + FALLBACK_PORTS if p != active_port]
    for port in ports:
        lines = await rcon(HOST, port, RCON_PASSWORD, f"dc {discord_id} {text}")
        if lines:
            return "\n".join(lines)
    return ("(сервер не ответил на RCON. Проверьте: `rcon_password` в server.cfg = SAMP_RCON_PASSWORD, "
            "`query 1` в server.cfg, порт и доступность UDP.)")


async def run(inter: discord.Interaction, text: str, owner_only: bool = False):
    allowed = is_owner(inter) if owner_only else is_admin(inter)
    if not allowed:
        log.warning("[deny] %s (%s) -> /%s", inter.user, inter.user.id, inter.command.name if inter.command else "?")
        return await inter.response.send_message(
            "Эта команда доступна только владельцу." if owner_only else "Нет доступа.", ephemeral=True)
    text = text.strip()
    if not text or len(text) > MAX_LEN or FORBIDDEN.search(text):
        return await inter.response.send_message("Недопустимые символы или слишком длинная команда.", ephemeral=True)
    await inter.response.defer(ephemeral=True)
    try:
        out = await send_to_server(inter.user.id, text)
        log.info("[exec] %s (%s): %s", inter.user, inter.user.id, text)
        await inter.followup.send(f"```\n{out[:1800]}\n```", ephemeral=True)
    except Exception as e:
        log.error("[rcon] %s", e)
        await inter.followup.send(f"Ошибка связи с сервером: {e}", ephemeral=True)


# ---------------------------------------------------------------- аккаунт игрока: привязка и восстановление пароля
# Любой участник Discord. Сервер проверяет код / привязку сам (account_discord.inc, команда RCON "dcu").
_recover_times: dict[int, list[float]] = {}
RECOVER_PER_HOUR = 3


async def send_user_to_server(discord_id: int, text: str) -> list[str]:
    if not RCON_PASSWORD:
        return ["ERROR: RCON-пароль не задан в .env"]
    ports = [active_port] + [p for p in [PORT] + FALLBACK_PORTS if p != active_port]
    for port in ports:
        lines = await rcon(HOST, port, RCON_PASSWORD, f"dcu {discord_id} {text}")
        if lines:
            return lines
    return ["ERROR: сервер не ответил"]


def _last_error(lines: list[str]) -> str:
    for l in lines:
        if l.startswith("ERROR:"):
            return l[6:].strip()
    return "сервер не ответил"


@bot.tree.command(name="link", description="Привязать игровой аккаунт к этому Discord (код из команды /discord в игре)")
@app_commands.describe(code="6 цифр из игры")
async def link(inter: discord.Interaction, code: app_commands.Range[int, 100000, 999999]):
    await inter.response.defer(ephemeral=True)
    lines = await send_user_to_server(inter.user.id, f"link {code}")
    ok = next((l for l in lines if l.startswith("OK LINKED")), None)
    if ok:
        login = ok.split(" ", 2)[2] if ok.count(" ") >= 2 else ""
        await inter.followup.send(f"Аккаунт **{login}** привязан к вашему Discord. Если забудете пароль - `/recover {login}`.", ephemeral=True)
    else:
        await inter.followup.send(f"Не получилось: {_last_error(lines)}", ephemeral=True)


@bot.tree.command(name="recover", description="Новый пароль для игрового аккаунта, привязанного к этому Discord")
@app_commands.describe(login="логин аккаунта в игре")
async def recover(inter: discord.Interaction, login: str):
    now = time.time()
    hist = [t for t in _recover_times.get(inter.user.id, []) if now - t < 3600]
    if len(hist) >= RECOVER_PER_HOUR:
        return await inter.response.send_message("Слишком часто. Попробуйте через час.", ephemeral=True)
    if not re.fullmatch(r"[A-Za-z0-9_]{3,20}", login or ""):
        return await inter.response.send_message("Логин: 3-20 символов, латинские буквы, цифры и _.", ephemeral=True)
    hist.append(now)
    _recover_times[inter.user.id] = hist
    await inter.response.defer(ephemeral=True)
    lines = await send_user_to_server(inter.user.id, f"recover {login}")
    got = next((l for l in lines if l.startswith("PASS ")), None)
    if got:
        parts = got.split(" ")
        acc, pwd = (parts[1], parts[2]) if len(parts) >= 3 else (login, "?")
        log.info("[recover] %s (%s) -> %s", inter.user, inter.user.id, acc)
        await inter.followup.send(
            f"Новый пароль для **{acc}**: `{pwd}`\nВойдите с ним в игру. Сообщение видно только вам - никому его не показывайте.",
            ephemeral=True)
    else:
        await inter.followup.send(f"Не получилось: {_last_error(lines)}", ephemeral=True)


@bot.tree.command(name="myaccounts", description="Игровые аккаунты, привязанные к этому Discord")
async def myaccounts(inter: discord.Interaction):
    await inter.response.defer(ephemeral=True)
    lines = await send_user_to_server(inter.user.id, "accounts")
    accs = [l[4:] for l in lines if l.startswith("ACC ")]
    if accs:
        await inter.followup.send("Привязаны: " + ", ".join(f"**{a}**" for a in accs), ephemeral=True)
    elif any(l.startswith("NONE") for l in lines):
        await inter.followup.send("Пока ничего не привязано. В игре: `/discord`, затем здесь `/link <код>`.", ephemeral=True)
    else:
        await inter.followup.send(f"Не получилось: {_last_error(lines)}", ephemeral=True)


# ---------------------------------------------------------------- команды в личных сообщениях боту
_dm_last: dict[int, float] = {}
DM_HELP_ALL = ("**Команды в личке бота** (пишите как в игре, со слешем):\n"
               "`/status` — сервер онлайн или нет\n`/online` — кто играет\n"
               "`/link 123456` — привязать игровой аккаунт (код из `/discord` в игре)\n`/myaccounts` — привязанные аккаунты")
DM_HELP_ADMIN = ("\n\n**Для админов бота** — те же команды, что `/srv` на сервере Discord:\n"
                 "`/ban 5 3 причина`, `/kick 5 причина`, `/warn 5 причина`, `/mute 5 10 причина`, `/jail 5 10 причина`,\n"
                 "`/givemoney 5 1000`, `/msg текст`, `/settime 12`, `/restart 5`, `/admins`, `/say текст` ...\n"
                 "`/srvhelp` — полный список с сервера.")


async def _dm_online_text() -> str:
    info = await probe_info()
    if not info:
        return "🔴 Сервер недоступен: " + (last_error or "нет ответа")
    if not info.players:
        return f"🟢 Сервер онлайн, игроков нет (0/{info.max_players})."
    try:
        players = await query.query_players(HOST, active_port)
    except Exception:
        return f"🟢 Онлайн: **{info.players}/{info.max_players}**."
    players.sort(key=lambda p: p.pid)
    lines = [f"`{p.pid:>3}` {p.name} · lvl {p.score} · {p.ping} мс" for p in players[:40]]
    more = f"\n... и ещё {len(players) - 40}" if len(players) > 40 else ""
    return f"🟢 Онлайн: **{info.players}/{info.max_players}**\n" + "\n".join(lines) + more


async def handle_dm(message: discord.Message):
    uid = message.author.id
    text = (message.content or "").strip()
    is_adm = str(uid) in ADMINS
    if not text.startswith("/"):
        return await message.channel.send(DM_HELP_ALL + (DM_HELP_ADMIN if is_adm else ""))
    now = time.time()
    if now - _dm_last.get(uid, 0.0) < 1.5:
        return await message.channel.send("Не так быстро: одна команда в 1,5 секунды.")
    _dm_last[uid] = now
    cmd = text[1:].strip()
    name, _, args = cmd.partition(" ")
    name = name.lower()

    # для всех
    if name in ("help", "помощь", "команды"):
        return await message.channel.send(DM_HELP_ALL + (DM_HELP_ADMIN if is_adm else ""))
    if name == "status":
        info = await probe_info()
        players = None
        if info and info.players:
            try:
                players = await query.query_players(HOST, active_port)
            except Exception:
                players = None
        return await message.channel.send(embed=status_embed(info, players))
    if name == "online":
        return await message.channel.send((await _dm_online_text())[:1900])
    if name == "link":
        if not re.fullmatch(r"\d{6}", args.strip()):
            return await message.channel.send("Напишите `/link 123456` — 6 цифр из команды `/discord` в игре.")
        lines = await send_user_to_server(uid, f"link {args.strip()}")
        ok = next((l for l in lines if l.startswith("OK LINKED")), None)
        if ok:
            login = ok.split(" ", 2)[2] if ok.count(" ") >= 2 else ""
            return await message.channel.send(f"Аккаунт **{login}** привязан к вашему Discord.")
        return await message.channel.send(f"Не получилось: {_last_error(lines)}")
    if name == "myaccounts":
        lines = await send_user_to_server(uid, "accounts")
        accs = [l[4:] for l in lines if l.startswith("ACC ")]
        if accs:
            return await message.channel.send("Привязаны: " + ", ".join(f"**{a}**" for a in accs))
        if any(l.startswith("NONE") for l in lines):
            return await message.channel.send("Пока ничего не привязано. В игре: `/discord`, затем здесь `/link <код>`.")
        return await message.channel.send(f"Не получилось: {_last_error(lines)}")

    # остальное - команды сервера, только админам бота (сервер ещё раз проверяет Discord ID и уровень команды)
    if not is_adm:
        log.warning("[dm deny] %s (%s): %s", message.author, uid, text[:80])
        return await message.channel.send("Эта команда доступна только администраторам бота. `/help` — что можно вам.")
    if name == "srvhelp":
        cmd = "help"
    if not cmd or len(cmd) > MAX_LEN or FORBIDDEN.search(cmd):
        return await message.channel.send("Недопустимые символы ( ' \" ` \\ % ; { } ) или слишком длинная команда.")
    async with message.channel.typing():
        out = await send_to_server(uid, cmd)
    log.info("[dm exec] %s (%s): %s", message.author, uid, cmd)
    out = out.strip() or "(сервер выполнил команду без ответа)"
    await message.channel.send(f"`/{cmd[:150]}`\n```\n{out[:1800]}\n```")


# ---------------------------------------------------------------- команды для всех
@bot.tree.command(name="status", description="Состояние игрового сервера")
@app_commands.guild_only()
async def status(inter: discord.Interaction):
    await inter.response.defer()
    info = await probe_info()
    players = None
    if info and info.players:
        try:
            players = await query.query_players(HOST, active_port)
        except Exception:
            players = None
    await inter.followup.send(embed=status_embed(info, players))


@bot.tree.command(name="online", description="Игроки онлайн")
@app_commands.guild_only()
async def online(inter: discord.Interaction):
    await inter.response.defer()
    info = await probe_info()
    if not info:
        return await inter.followup.send(embed=status_embed(None))
    if not info.players:
        return await inter.followup.send("🟢 Сервер онлайн, игроков нет.")
    try:
        players = await query.query_players(HOST, active_port)
    except Exception:
        return await inter.followup.send(
            f"🟢 Онлайн: **{info.players}/{info.max_players}** (список недоступен: при >100 игроков сервер его не отдаёт).")
    players.sort(key=lambda p: p.pid)
    lines = [f"`{p.pid:>3}` {p.name}  · lvl {p.score} · {p.ping} мс" for p in players]
    e = discord.Embed(title=f"Онлайн: {info.players}/{info.max_players}", colour=0x2ECC71)
    chunk, field_no = "", 1
    for line in lines:
        if len(chunk) + len(line) + 1 > 1000:
            e.add_field(name="Игроки" if field_no == 1 else "\u200b", value=chunk, inline=False)
            chunk, field_no = "", field_no + 1
        chunk += line + "\n"
    if chunk:
        e.add_field(name="Игроки" if field_no == 1 else "\u200b", value=chunk, inline=False)
    await inter.followup.send(embed=e)


# ---------------------------------------------------------------- команды для админов бота
@bot.tree.command(name="srv", description="Команда администратора на игровой сервер (напр. ban 5 3 причина; help - список)")
@app_commands.describe(command="команда и аргументы")
@app_commands.guild_only()
async def srv(inter: discord.Interaction, command: str):
    await run(inter, command)


@bot.tree.command(name="say", description="Сообщение всем игрокам от имени Discord")
@app_commands.describe(text="текст")
@app_commands.guild_only()
async def say(inter: discord.Interaction, text: str):
    await run(inter, "say " + text)


@bot.tree.command(name="admins", description="Игровые администраторы (онлайн и в базе)")
@app_commands.guild_only()
async def admins(inter: discord.Interaction):
    await run(inter, "admins")


# ---------------------------------------------------------------- только владелец
@bot.tree.command(name="setadmin", description="Назначить игрового администратора (только владелец)")
@app_commands.describe(nick="ник игрока на сервере", level="уровень администратора (1-6)")
@app_commands.guild_only()
async def setadmin(inter: discord.Interaction, nick: str, level: app_commands.Range[int, 1, 6]):
    if not NICK_RE.fullmatch(nick):
        return await inter.response.send_message("Некорректный ник.", ephemeral=True)
    await run(inter, f"setadmin {nick} {level}", owner_only=True)


@bot.tree.command(name="removeadmin", description="Снять игрового администратора (только владелец)")
@app_commands.describe(nick="ник игрока на сервере")
@app_commands.guild_only()
async def removeadmin(inter: discord.Interaction, nick: str):
    if not NICK_RE.fullmatch(nick):
        return await inter.response.send_message("Некорректный ник.", ephemeral=True)
    await run(inter, f"removeadmin {nick}", owner_only=True)


# ---------------------------------------------------------------- логи сервера -> Discord
store = logstore.Store(DB_FILE)
chan_cfg = logstore.ChannelConfig(CONFIG_FILE)
_log_runner = None


# ---------------------------------------------------------------- вход через Google и персонажи для лаунчера
# Код в stage_api.py: он же запускается отдельно, без Discord (python stage_api.py), если бот не нужен.
import stage_api


async def start_log_services():
    """Запуск HTTP-приёмника логов (POST /log), рассылки в каналы и чистки старых записей."""
    global _log_runner
    if not LOG_SECRET or len(LOG_SECRET) < 12:
        log.warning("[logs] LOG_SECRET не задан (или короче 12 символов): приём логов с сервера ВЫКЛЮЧЕН")
    else:
        from aiohttp import web
        app = logstore.make_log_app(store, LOG_SECRET, log, STATS_PAGE_KEY)
        stage_api.add_routes(app, LOG_SECRET, log)     # POST /google (для игрового сервера) и POST /chars (для лаунчера)
        _log_runner = web.AppRunner(app)
        await _log_runner.setup()
        await web.TCPSite(_log_runner, LOG_HTTP_HOST, LOG_HTTP_PORT).start()
        log.info("[logs] приём логов: http://%s:%d/log, статистика: http://%s:%d/stats%s", LOG_HTTP_HOST, LOG_HTTP_PORT, LOG_HTTP_HOST, LOG_HTTP_PORT, "?key=..." if STATS_PAGE_KEY else "")
    dispatch_logs.start()
    prune_logs.start()
    weekly_report.start()


async def _get_channel(channel_id: int):
    ch = bot.get_channel(channel_id)
    if ch is None:
        try:
            ch = await bot.fetch_channel(channel_id)
        except (discord.NotFound, discord.Forbidden):
            return None
    return ch


MAX_MSGS_PER_CHANNEL = 5  # за один цикл (~5 с), остальное уйдёт в следующем - так не упираемся в лимиты Discord


@tasks.loop(seconds=5)
async def dispatch_logs():
    rows = store.pending(300)
    if not rows:
        return
    done: list[int] = []
    by_channel: dict[int, list] = {}
    for rid, ts, cat, nick, text in rows:
        ch_id = chan_cfg.channel_for(cat)
        if not ch_id:
            done.append(rid)  # канал не выбран: запись остаётся в базе для поиска
            continue
        by_channel.setdefault(ch_id, []).append((rid, logstore.fmt_line(ts, cat, nick, text)))
    for ch_id, items in by_channel.items():
        channel = await _get_channel(ch_id)
        if channel is None:
            log.warning("[logs] канал %s недоступен, записи пропущены", ch_id)
            done.extend(r for r, _ in items)
            continue
        messages, cur_ids, cur_text = [], [], ""
        for rid, line in items:
            line = line[:1900]
            if cur_text and len(cur_text) + 1 + len(line) > 1900:
                messages.append((cur_ids, cur_text))
                cur_ids, cur_text = [], ""
            cur_text = f"{cur_text}\n{line}" if cur_text else line
            cur_ids.append(rid)
        if cur_text:
            messages.append((cur_ids, cur_text))
        for ids, text in messages[:MAX_MSGS_PER_CHANNEL]:
            try:
                await channel.send(text, allowed_mentions=discord.AllowedMentions.none())
                done.extend(ids)
            except (discord.Forbidden, discord.NotFound) as e:
                log.warning("[logs] нет доступа к каналу %s: %s", ch_id, e)
                done.extend(r for r, _ in items)
                break
            except discord.HTTPException as e:
                log.warning("[logs] ошибка отправки в %s: %s (повтор позже)", ch_id, e)
                break
            await asyncio.sleep(0.6)
    store.mark_sent(done)


@dispatch_logs.before_loop
async def _wait_ready_logs():
    await bot.wait_until_ready()


@tasks.loop(hours=1)
async def prune_logs():
    n = store.prune()
    if n:
        log.info("[logs] удалено старых записей: %d", n)


CAT_CHOICES = [app_commands.Choice(name=c, value=c) for c in logstore.CATEGORIES]


def _deny(inter, owner_only=False):
    return inter.response.send_message(
        "Эта команда доступна только владельцу." if owner_only else "Нет доступа.", ephemeral=True)


@bot.tree.command(name="setlogchannel", description="Куда слать логи категории (только владелец)")
@app_commands.describe(category="категория логов или all (по умолчанию)", channel="текстовый канал")
@app_commands.choices(category=CAT_CHOICES + [app_commands.Choice(name="all (все остальные)", value="all")])
@app_commands.guild_only()
async def setlogchannel(inter: discord.Interaction, category: app_commands.Choice[str], channel: discord.TextChannel):
    if not is_owner(inter):
        return await _deny(inter, True)
    perms = channel.permissions_for(inter.guild.me)
    if not (perms.view_channel and perms.send_messages):
        return await inter.response.send_message(
            f"У бота нет прав писать в {channel.mention} (нужны «Просмотр канала» и «Отправка сообщений»).", ephemeral=True)
    chan_cfg.set(category.value, channel.id)
    await inter.response.send_message(f"Логи `{category.value}` -> {channel.mention}", ephemeral=True)


@bot.tree.command(name="clearlogchannel", description="Убрать канал для категории логов (только владелец)")
@app_commands.choices(category=CAT_CHOICES + [app_commands.Choice(name="all (все остальные)", value="all")])
@app_commands.guild_only()
async def clearlogchannel(inter: discord.Interaction, category: app_commands.Choice[str]):
    if not is_owner(inter):
        return await _deny(inter, True)
    ok = chan_cfg.clear(category.value)
    await inter.response.send_message("Канал для `%s` убран." % category.value if ok else "Для этой категории канал не задан.",
                                      ephemeral=True)


@bot.tree.command(name="logchannels", description="Каналы для логов (только владелец)")
@app_commands.guild_only()
async def logchannels(inter: discord.Interaction):
    if not is_owner(inter):
        return await _deny(inter, True)
    lines = []
    for c in logstore.CATEGORIES + ["all"]:
        cid = chan_cfg.data.get(c)
        lines.append(f"`{c}` -> " + (f"<#{cid}>" if cid else "не задан"))
    await inter.response.send_message("\n".join(lines) + "\n`stats` в каналы не рассылается.", ephemeral=True)


async def _send_found(inter: discord.Interaction, rows, title: str):
    if not rows:
        return await inter.followup.send("Ничего не найдено.", ephemeral=True)
    lines = [logstore.fmt_line(ts, cat, nick, text) for ts, cat, nick, text in rows]
    head = f"**{title}** (найдено {len(rows)}, новые сверху)\n"
    out = head
    for ln in lines:
        if len(out) + len(ln) + 1 > 1900:
            break
        out += ln + "\n"
    await inter.followup.send(out, ephemeral=True, allowed_mentions=discord.AllowedMentions.none())


@bot.tree.command(name="adminlog", description="Журнал действий админа по нику (админы бота)")
@app_commands.describe(nick="ник админа (или игрока, упомянутого в действии)", days="за сколько дней (1-30)")
@app_commands.guild_only()
async def adminlog(inter: discord.Interaction, nick: str, days: app_commands.Range[int, 1, 30] = 7):
    if not is_admin(inter):
        return await _deny(inter)
    await inter.response.defer(ephemeral=True)
    rows = store.search(nick.strip()[:32], ["admin", "adminchat"], days, 25)
    await _send_found(inter, rows, f"Журнал админа {nick} за {days} дн.")


@bot.tree.command(name="searchlog", description="Поиск в логах по нику (админы бота)")
@app_commands.describe(nick="ник игрока", category="категория (по умолчанию все)", days="за сколько дней (1-30)")
@app_commands.choices(category=CAT_CHOICES)
@app_commands.guild_only()
async def searchlog(inter: discord.Interaction, nick: str, category: app_commands.Choice[str] | None = None,
                    days: app_commands.Range[int, 1, 30] = 7):
    if not is_admin(inter):
        return await _deny(inter)
    await inter.response.defer(ephemeral=True)
    cats = [category.value] if category else None
    rows = store.search(nick.strip()[:32], cats, days, 25)
    await _send_found(inter, rows, f"Поиск {nick}" + (f" [{category.value}]" if category else "") + f" за {days} дн.")


@bot.tree.command(name="stats", description="Онлайн по дням, деньги в обороте, топ жалоб (админы бота)")
@app_commands.describe(days="за сколько дней (1-30)")
@app_commands.guild_only()
async def stats(inter: discord.Interaction, days: app_commands.Range[int, 1, 30] = 7):
    if not is_admin(inter):
        return await _deny(inter)
    await inter.response.defer(ephemeral=True)
    await inter.followup.send(logstore.build_stats_text(store, days)[:1950], ephemeral=True)


@bot.tree.command(name="player", description="Карточка игрока по логам (админы бота)")
@app_commands.describe(nick="ник игрока", days="за сколько дней (1-30)")
@app_commands.guild_only()
async def player_card(inter: discord.Interaction, nick: str, days: app_commands.Range[int, 1, 30] = 7):
    if not is_admin(inter):
        return await _deny(inter)
    await inter.response.defer(ephemeral=True)
    nick = nick.strip()[:32]
    last_join, by_cat, recent = store.player_card(nick, days)
    if not last_join and not by_cat:
        return await inter.followup.send("По этому нику ничего нет в логах.", ephemeral=True)
    out = [f"**{nick}** за {days} дн."]
    if last_join:
        out.append("Последний вход/выход: " + logstore.fmt_line(last_join[0], "join", nick, last_join[1], False))
    if by_cat:
        out.append("Записей по категориям: " + ", ".join(f"{c}: {n}" for c, n in by_cat))
    for ts, cat, n, text in recent:
        out.append(logstore.fmt_line(ts, cat, n, text))
    await inter.followup.send("\n".join(out)[:1900], ephemeral=True, allowed_mentions=discord.AllowedMentions.none())


@tasks.loop(hours=1)
async def weekly_report():
    """По понедельникам в 10:00 (время бота) - сводка за 7 дней в канал категории server (или all)."""
    now = time.localtime()
    week = now.tm_year * 100 + int(time.strftime("%W", now))
    if now.tm_wday != 0 or now.tm_hour != 10 or chan_cfg.data.get("_weekly") == week:
        return
    ch_id = chan_cfg.channel_for("server")
    if not ch_id:
        return
    channel = await _get_channel(ch_id)
    if channel is None:
        return
    chan_cfg.data["_weekly"] = week
    chan_cfg.save()
    await channel.send("**Недельный отчёт**\n" + logstore.build_stats_text(store, 7)[:1900],
                       allowed_mentions=discord.AllowedMentions.none())


@bot.tree.error
async def on_error(inter: discord.Interaction, error: app_commands.AppCommandError):
    log.error("[command] %s", error)
    try:
        if inter.response.is_done():
            await inter.followup.send("Ошибка выполнения команды.", ephemeral=True)
        else:
            await inter.response.send_message("Ошибка выполнения команды.", ephemeral=True)
    except Exception:
        pass


# ---------------------------------------------------------------- самопроверка
async def selftest():
    print(f"Хост: {HOST}   порт (.env): {PORT}   запасные: {FALLBACK_PORTS}")
    print(f"Владелец: {OWNER}   админы бота: {sorted(ADMINS)}")
    info = await probe_info()
    if info:
        print(f"[OK] query: {info.hostname}  {info.players}/{info.max_players}  порт {info.port}  пинг {info.ping_ms} мс")
        if info.port != PORT:
            print(f"[!] В .env укажите SAMP_PORT={info.port}")
    else:
        print(f"[ОШИБКА] query: {last_error}")
        print("    - сервер выключен, либо неверный SAMP_HOST/SAMP_PORT, либо закрыт UDP-порт,")
        print("    - либо в server.cfg нет строки `query 1`.")
    if RCON_PASSWORD and info:
        try:
            out = await send_to_server(int(OWNER), "online")
            print("[RCON] ответ:", out.replace("\n", " | ")[:200])
        except Exception as e:
            print("[ОШИБКА] RCON:", e)
    await selftest_http()


async def selftest_http():
    """Проверка приёма логов: имитация POST из Pawn (тот же формат тела) на временной базе."""
    import aiohttp
    from aiohttp import web
    from urllib.parse import quote_from_bytes

    secret = LOG_SECRET or "selftest-secret-123456"
    tmp = logstore.Store(":memory:")
    runner = web.AppRunner(logstore.make_log_app(tmp, secret))
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    url = f"http://127.0.0.1:{port}/log"

    def enc(text):  # как dclog_urlencode в Pawn: по байтам cp1251
        return quote_from_bytes(text.encode("cp1251"), safe="-_.")

    rows = "report\tIvan_Test\tв машине читер, ГОНЯЕТ\nstats\tserver\tonline=12\nadmin\tAdmin_One\tban Ivan_Test 3 дня"
    good = f"key={enc(secret)}&d={enc(rows)}".encode()
    ok = True
    async with aiohttp.ClientSession() as s:
        async with s.post(url, data=good, headers={"Content-Type": "application/x-www-form-urlencoded"}) as r:
            ok &= r.status == 200
            print("[HTTP] верный секрет ->", r.status, "(ожидаем 200)")
        async with s.post(url, data=f"key=wrong&d={enc(rows)}".encode()) as r:
            ok &= r.status == 403
            print("[HTTP] неверный секрет ->", r.status, "(ожидаем 403)")
        async with s.post(url, data=b"x" * 70000) as r:
            ok &= r.status == 413
            print("[HTTP] тело 70 КБ ->", r.status, "(ожидаем 413)")
    async with aiohttp.ClientSession() as s2:
        async with s2.get(f"http://127.0.0.1:{port}/stats") as r:
            body = await r.text()
            ok &= r.status == 200 and "Онлайн по дням" in body
            print("[HTTP] страница /stats ->", r.status, "(ожидаем 200)")
        async with s2.get(f"http://127.0.0.1:{port}/stats.json") as r:
            ok &= r.status == 200
            print("[HTTP] /stats.json ->", r.status)
    got = tmp.search("Ivan_Test", None, 1, 10)
    ok &= len(got) == 2 and any("читер" in g[3] for g in got)
    ok &= bool(tmp.online_by_day(1))
    print("[HTTP] в базе:", [(g[1], g[2]) for g in got], "| статистика онлайна:", bool(tmp.online_by_day(1)))
    await runner.cleanup()
    print("[HTTP] ИТОГ:", "OK" if ok else "ОШИБКА")


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        asyncio.run(selftest())
    else:
        bot.run(TOKEN, log_handler=None)
