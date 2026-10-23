import os
import json
import html
import secrets
import sqlite3
import urllib.parse
import urllib.request
import urllib.error
from functools import wraps

from flask import (
    Flask, jsonify, request, session, redirect,
    render_template, render_template_string, url_for
)

app = Flask(__name__)

SECRET_KEY = os.environ.get("FLASK_SECRET_KEY") or os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("Set FLASK_SECRET_KEY in Render Environment.")
app.secret_key = SECRET_KEY

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=bool(os.environ.get("RENDER")),
    PERMANENT_SESSION_LIFETIME=60 * 60 * 12,
)

DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
DB_PATH = os.environ.get("DB_PATH", "dashboard.sqlite3")
DASHBOARD_API_KEY = os.environ.get("DASHBOARD_API_KEY", "").strip()
DASHBOARD_PASSWORD = os.environ.get("DASHBOARD_PASSWORD", "")

DISCORD_CLIENT_ID = os.environ.get("DISCORD_CLIENT_ID", "").strip()
DISCORD_CLIENT_SECRET = os.environ.get("DISCORD_CLIENT_SECRET", "").strip()
DISCORD_REDIRECT_URI = os.environ.get("DISCORD_REDIRECT_URI", "").strip()

DISCORD_API = "https://discord.com/api/v10"
DISCORD_OAUTH = "https://discord.com/api/oauth2"
MAX_TRANSCRIPT_LENGTH = 1_000_000

DEFAULT_CONFIG = {
    "panel": {
        "title": "مركز الدعم الفني",
        "description": "مرحبًا بك! اختر القسم المناسب من القائمة أدناه لفتح تذكرة جديدة.",
        "button_label": "فتح تذكرة",
        "color": "#7865f5"
    },
    "behavior": {
        "one_ticket_per_user": True,
        "welcome_message_enabled": True,
        "transcript_enabled": False
    },
    "channels": {
        "log_channel_id": "",
        "ticket_category_id": "",
        "panel_channel_id": ""
    },
    "points": {
        "single_point_per_ticket": True,
        "staff_logs_enabled": True
    },
    "messages": {
        "welcome": "أهلًا بك {user}، وضّح طلبك وسيقوم فريق الدعم بمساعدتك قريبًا.",
        "close": "تم إغلاق التذكرة بواسطة {staff}."
    },
    "categories": [
        {"name": "الدعم الفني", "desc": "مساعدة في المشاكل التقنية", "active": True},
        {"name": "الاستفسارات العامة", "desc": "أسئلة واستفسارات", "active": True},
        {"name": "الشكاوى والاقتراحات", "desc": "أرسل ملاحظتك للإدارة", "active": True}
    ],
    "staff": []
}


# ---------------- DATABASE ----------------

def db():
    if DATABASE_URL:
        import psycopg
        from psycopg.rows import dict_row

        con = psycopg.connect(DATABASE_URL, row_factory=dict_row)

        con.execute("""
            CREATE TABLE IF NOT EXISTS configs (
                guild_id TEXT PRIMARY KEY,
                config_json TEXT NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        con.execute("""
            CREATE TABLE IF NOT EXISTS ticket_archives (
                channel_id TEXT PRIMARY KEY,
                archive_token TEXT UNIQUE NOT NULL,
                guild_id TEXT NOT NULL,
                ticket_number TEXT NOT NULL,
                owner_id TEXT NOT NULL,
                closed_by TEXT NOT NULL,
                closed_at TEXT,
                ticket_type TEXT NOT NULL,
                transcript TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        return con

    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row

    con.execute("""
        CREATE TABLE IF NOT EXISTS configs (
            guild_id TEXT PRIMARY KEY,
            config_json TEXT NOT NULL,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    con.execute("""
        CREATE TABLE IF NOT EXISTS ticket_archives (
            channel_id TEXT PRIMARY KEY,
            archive_token TEXT UNIQUE NOT NULL,
            guild_id TEXT NOT NULL,
            ticket_number TEXT NOT NULL,
            owner_id TEXT NOT NULL,
            closed_by TEXT NOT NULL,
            closed_at TEXT,
            ticket_type TEXT NOT NULL,
            transcript TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    return con


def discord_api(path, data=None, access_token=None, oauth=False):
    headers = {"User-Agent": "TicketControlDashboard/1.0"}
    body = None
    base = DISCORD_OAUTH if oauth else DISCORD_API

    if access_token:
        headers["Authorization"] = "Bearer " + access_token

    if data is not None:
        body = urllib.parse.urlencode(data).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"

    req = urllib.request.Request(
        base + path,
        data=body,
        headers=headers,
        method="POST" if data is not None else "GET"
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            return json.loads(response.read().decode())
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as exc:
        app.logger.warning("Discord API request failed: %s", exc)
        raise ValueError("Discord API request failed") from exc


# ---------------- AUTHENTICATION ----------------

def password_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not DASHBOARD_PASSWORD:
            return jsonify({"error": "password_not_configured"}), 503

        if not session.get("password_ok"):
            return jsonify({"error": "password_required"}), 401

        return fn(*args, **kwargs)
    return wrapped


def require_login(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not DASHBOARD_PASSWORD:
            return jsonify({"error": "password_not_configured"}), 503

        if not session.get("password_ok"):
            return jsonify({"error": "password_required"}), 401

        if not session.get("discord_user_id"):
            return jsonify({"error": "login_required"}), 401

        return fn(*args, **kwargs)
    return wrapped


def valid_bot_key():
    supplied = request.headers.get("X-Dashboard-Key", "")
    return bool(
        DASHBOARD_API_KEY
        and supplied
        and secrets.compare_digest(supplied, DASHBOARD_API_KEY)
    )


def selected_guild():
    guild_id = str(
        request.args.get("guild_id")
        or session.get("selected_guild_id")
        or ""
    )

    if guild_id not in session.get("manageable_guild_ids", []):
        return None

    return guild_id


# ---------------- PASSWORD PAGE ----------------

PASSWORD_PAGE = """
<!doctype html>
<html lang="ar" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>حماية لوحة التكت</title>
<style>
*{box-sizing:border-box}
body{
  margin:0;min-height:100vh;display:grid;place-items:center;
  background:#10121a;color:#f4f4fa;font-family:Arial,sans-serif
}
form{
  width:min(370px,90vw);padding:28px;background:#1b1e2b;
  border:1px solid #34384c;border-radius:16px
}
input,button{
  width:100%;padding:13px;margin-top:13px;border-radius:8px
}
input{background:#10121a;color:white;border:1px solid #454960}
button{background:#7865f5;color:white;border:0;cursor:pointer;font-weight:bold}
.error{color:#ff9b9b}
</style>
</head>
<body>
<form method="post">
<h2>🔒 حماية لوحة التكت</h2>
<p>أدخل كلمة السر للمتابعة إلى تسجيل دخول ديسكورد.</p>
{% if error %}<p class="error">{{ error }}</p>{% endif %}
<input name="password" type="password" placeholder="كلمة السر" required autofocus>
<button type="submit">متابعة</button>
</form>
</body>
</html>
"""


@app.route("/password", methods=["GET", "POST"])
def password_login():
    if not DASHBOARD_PASSWORD:
        return "أضف DASHBOARD_PASSWORD في Render Environment.", 503

    if request.method == "POST":
        supplied = request.form.get("password", "")

        if secrets.compare_digest(supplied, DASHBOARD_PASSWORD):
            session.clear()
            session["password_ok"] = True
            session.permanent = True
            return redirect(url_for("login"))

        return render_template_string(
            PASSWORD_PAGE, error="كلمة السر غير صحيحة."
        ), 401

    if session.get("password_ok"):
        return redirect(
            url_for("index") if session.get("discord_user_id")
            else url_for("login")
        )

    return render_template_string(PASSWORD_PAGE, error="")


# ---------------- MAIN ----------------

@app.get("/")
def index():
    if not DASHBOARD_PASSWORD:
        return "إعداد DASHBOARD_PASSWORD غير موجود في Render.", 503

    if not session.get("password_ok"):
        return redirect(url_for("password_login"))

    if not session.get("discord_user_id"):
        return redirect(url_for("login"))

    return render_template("index.html")


@app.get("/health")
def health():
    return jsonify({"ok": True, "service": "ticket-dashboard"})


# ---------------- DISCORD LOGIN ----------------

@app.get("/login")
def login():
    if not DASHBOARD_PASSWORD:
        return "إعداد DASHBOARD_PASSWORD غير موجود في Render.", 503

    if not session.get("password_ok"):
        return redirect(url_for("password_login"))

    if not all((
        DISCORD_CLIENT_ID,
        DISCORD_CLIENT_SECRET,
        DISCORD_REDIRECT_URI
    )):
        return "إعدادات Discord OAuth غير مكتملة في Render.", 503

    state = secrets.token_urlsafe(32)
    session["oauth_state"] = state

    params = {
        "client_id": DISCORD_CLIENT_ID,
        "redirect_uri": DISCORD_REDIRECT_URI,
        "response_type": "code",
        "scope": "identify guilds",
        "state": state
    }

    return redirect(
        "https://discord.com/oauth2/authorize?"
        + urllib.parse.urlencode(params)
    )


@app.get("/oauth/callback")
def oauth_callback():
    if not session.get("password_ok"):
        return redirect(url_for("password_login"))

    expected = session.pop("oauth_state", None)
    received = request.args.get("state", "")

    if not expected or not secrets.compare_digest(expected, received):
        return "فشل التحقق من تسجيل الدخول. حاول مرة أخرى.", 400

    if request.args.get("error"):
        return redirect(url_for("login"))

    code = request.args.get("code")
    if not code:
        return "لم يصل رمز تسجيل الدخول.", 400

    try:
        token = discord_api("/token", data={
            "client_id": DISCORD_CLIENT_ID,
            "client_secret": DISCORD_CLIENT_SECRET,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": DISCORD_REDIRECT_URI
        }, oauth=True)

        access_token = token["access_token"]
        user = discord_api("/users/@me", access_token=access_token)
        guilds = discord_api("/users/@me/guilds", access_token=access_token)

        manageable = []

        for guild in guilds:
            try:
                permissions = int(guild.get("permissions", "0"))
            except (ValueError, TypeError):
                permissions = 0

            if permissions & 32 or permissions & 8:
                manageable.append({
                    "id": str(guild["id"]),
                    "name": str(guild.get("name", "Discord")),
                    "icon": guild.get("icon")
                })

        # Keep the password session while replacing OAuth data.
        session["discord_user_id"] = str(user["id"])
        session["discord_username"] = (
            user.get("global_name")
            or user.get("username")
            or "Discord user"
        )
        session["manageable_guilds"] = manageable
        session["manageable_guild_ids"] = [
            guild["id"] for guild in manageable
        ]

        if manageable:
            session["selected_guild_id"] = manageable[0]["id"]

        return redirect(url_for("index") + "?login=success")

    except (ValueError, KeyError, TypeError):
        return (
            "تعذر تسجيل الدخول. تحقق من إعدادات OAuth وRedirect URI.",
            502
        )


@app.get("/api/me")
@password_required
def me():
    if not session.get("discord_user_id"):
        return jsonify({"logged_in": False})

    return jsonify({
        "logged_in": True,
        "user": {
            "id": session["discord_user_id"],
            "username": session.get("discord_username")
        },
        "guilds": session.get("manageable_guilds", []),
        "selected_guild_id": session.get("selected_guild_id")
    })


@app.post("/api/select-guild")
@require_login
def select_guild():
    payload = request.get_json(silent=True) or {}
    guild_id = str(payload.get("guild_id", ""))

    if guild_id not in session.get("manageable_guild_ids", []):
        return jsonify({"error": "guild_forbidden"}), 403

    session["selected_guild_id"] = guild_id
    return jsonify({"ok": True, "guild_id": guild_id})


@app.post("/logout")
def logout():
    session.clear()
    return jsonify({"ok": True})


# ---------------- CONFIG ----------------

@app.get("/api/config")
@require_login
def get_config():
    guild_id = selected_guild()

    if not guild_id:
        return jsonify({"error": "select_guild"}), 400

    sql = (
        "SELECT config_json FROM configs WHERE guild_id = %s"
        if DATABASE_URL else
        "SELECT config_json FROM configs WHERE guild_id = ?"
    )

    with db() as con:
        row = con.execute(sql, (guild_id,)).fetchone()

    config = json.loads(row["config_json"]) if row else DEFAULT_CONFIG

    return jsonify({"guild_id": guild_id, "config": config})


@app.put("/api/config")
@require_login
def put_config():
    guild_id = selected_guild()

    if not guild_id:
        return jsonify({"error": "select_guild"}), 400

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "invalid_json"}), 400

    allowed = (
        "panel", "behavior", "channels",
        "points", "messages", "categories", "staff"
    )

    config = {key: payload[key] for key in allowed if key in payload}
    data = json.dumps(config, ensure_ascii=False)

    sql = (
        """INSERT INTO configs (guild_id, config_json, updated_at)
           VALUES (%s, %s, CURRENT_TIMESTAMP)
           ON CONFLICT (guild_id) DO UPDATE SET
           config_json = EXCLUDED.config_json,
           updated_at = CURRENT_TIMESTAMP"""
        if DATABASE_URL else
        """INSERT INTO configs (guild_id, config_json, updated_at)
           VALUES (?, ?, CURRENT_TIMESTAMP)
           ON CONFLICT(guild_id) DO UPDATE SET
           config_json = excluded.config_json,
           updated_at = CURRENT_TIMESTAMP"""
    )

    with db() as con:
        con.execute(sql, (guild_id, data))

    return jsonify({"ok": True, "guild_id": guild_id})


# ---------------- ARCHIVE SEARCH ----------------

@app.get("/api/archives")
@require_login
def list_archives():
    guild_id = selected_guild()

    if not guild_id:
        return jsonify({"error": "select_guild"}), 400

    query = request.args.get("q", "").strip()[:100]
    limit = min(max(request.args.get("limit", 50, type=int), 1), 100)
    placeholder = "%s" if DATABASE_URL else "?"

    sql = f"""
        SELECT channel_id, ticket_number, owner_id, closed_by,
               closed_at, ticket_type, created_at
        FROM ticket_archives
        WHERE guild_id = {placeholder}
    """
    params = [guild_id]

    if query:
        sql += f""" AND (
            ticket_number LIKE {placeholder}
            OR owner_id LIKE {placeholder}
            OR closed_by LIKE {placeholder}
            OR ticket_type LIKE {placeholder}
        )"""
        pattern = "%" + query + "%"
        params.extend([pattern] * 4)

    sql += " ORDER BY created_at DESC LIMIT " + str(limit)

    with db() as con:
        rows = con.execute(sql, tuple(params)).fetchall()

    archives = [{
        "channel_id": str(row["channel_id"]),
        "ticket_number": str(row["ticket_number"]),
        "owner_id": str(row["owner_id"]),
        "closed_by": str(row["closed_by"]),
        "closed_at": str(row["closed_at"] or ""),
        "ticket_type": str(row["ticket_type"]),
        "created_at": str(row["created_at"] or "")
    } for row in rows]

    return jsonify({"archives": archives})


@app.get("/api/archives/<channel_id>")
@require_login
def archive_detail(channel_id):
    guild_id = selected_guild()

    if not guild_id:
        return jsonify({"error": "select_guild"}), 400

    placeholder = "%s" if DATABASE_URL else "?"

    with db() as con:
        row = con.execute(
            f"""SELECT channel_id, ticket_number, owner_id, closed_by,
                       closed_at, ticket_type, transcript, created_at
                FROM ticket_archives
                WHERE guild_id = {placeholder}
                  AND channel_id = {placeholder}""",
            (guild_id, str(channel_id))
        ).fetchone()

    if not row:
        return jsonify({"error": "not_found"}), 404

    return jsonify({"archive": {
        "channel_id": str(row["channel_id"]),
        "ticket_number": str(row["ticket_number"]),
        "owner_id": str(row["owner_id"]),
        "closed_by": str(row["closed_by"]),
        "closed_at": str(row["closed_at"] or ""),
        "ticket_type": str(row["ticket_type"]),
        "transcript": str(row["transcript"]),
        "created_at": str(row["created_at"] or "")
    }})


# ---------------- BOT API ----------------

@app.get("/api/bot/config")
def bot_config():
    if not valid_bot_key():
        return jsonify({"error": "unauthorized"}), 401

    guild_id = request.args.get("guild_id", "").strip()
    if not guild_id:
        return jsonify({"error": "missing_guild_id"}), 400

    sql = (
        "SELECT config_json, updated_at FROM configs WHERE guild_id = %s"
        if DATABASE_URL else
        "SELECT config_json, updated_at FROM configs WHERE guild_id = ?"
    )

    with db() as con:
        row = con.execute(sql, (guild_id,)).fetchone()

    config = json.loads(row["config_json"]) if row else DEFAULT_CONFIG

    return jsonify({
        "guild_id": guild_id,
        "config": config,
        "updated_at": str(row["updated_at"]) if row else None
    })


@app.post("/api/bot/archive")
def receive_archive():
    if not valid_bot_key():
        return jsonify({"error": "unauthorized"}), 401

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "invalid_json"}), 400

    required = (
        "guild_id", "channel_id", "ticket_number",
        "owner_id", "closed_by", "ticket_type", "transcript"
    )

    if any(payload.get(key) is None for key in required):
        return jsonify({"error": "missing_fields", "required": required}), 400

    values = {
        key: str(payload[key]).strip()
        for key in (
            "guild_id", "channel_id", "ticket_number",
            "owner_id", "closed_by", "ticket_type"
        )
    }

    transcript = payload["transcript"]
    closed_at = str(payload.get("closed_at") or "")

    if not all(values.values()):
        return jsonify({"error": "empty_fields"}), 400

    if not isinstance(transcript, str) or not transcript.strip():
        return jsonify({"error": "invalid_transcript"}), 400

    if len(transcript) > MAX_TRANSCRIPT_LENGTH:
        return jsonify({"error": "transcript_too_large"}), 413

    placeholder = "%s" if DATABASE_URL else "?"

    with db() as con:
        row = con.execute(
            f"SELECT archive_token FROM ticket_archives WHERE channel_id = {placeholder}",
            (values["channel_id"],)
        ).fetchone()

        if row:
            token = row["archive_token"]

            sql = (
                """UPDATE ticket_archives SET guild_id=%s,
                   ticket_number=%s, owner_id=%s, closed_by=%s,
                   closed_at=%s, ticket_type=%s, transcript=%s
                   WHERE channel_id=%s"""
                if DATABASE_URL else
                """UPDATE ticket_archives SET guild_id=?,
                   ticket_number=?, owner_id=?, closed_by=?,
                   closed_at=?, ticket_type=?, transcript=?
                   WHERE channel_id=?"""
            )

            con.execute(sql, (
                values["guild_id"], values["ticket_number"],
                values["owner_id"], values["closed_by"], closed_at,
                values["ticket_type"], transcript, values["channel_id"]
            ))
        else:
            token = secrets.token_urlsafe(32)

            sql = (
                """INSERT INTO ticket_archives (
                    channel_id, archive_token, guild_id, ticket_number,
                    owner_id, closed_by, closed_at, ticket_type, transcript
                ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)"""
                if DATABASE_URL else
                """INSERT INTO ticket_archives (
                    channel_id, archive_token, guild_id, ticket_number,
                    owner_id, closed_by, closed_at, ticket_type, transcript
                ) VALUES (?,?,?,?,?,?,?,?,?)"""
            )

            con.execute(sql, (
                values["channel_id"], token, values["guild_id"],
                values["ticket_number"], values["owner_id"],
                values["closed_by"], closed_at,
                values["ticket_type"], transcript
            ))

    return jsonify({
        "ok": True,
        "archive_url": url_for(
            "view_archive", token=token, _external=True
        )
    }), 201


@app.get("/archive/<token>")
def view_archive(token):
    placeholder = "%s" if DATABASE_URL else "?"

    with db() as con:
        row = con.execute(
            f"""SELECT ticket_number, owner_id, closed_by, closed_at,
                       ticket_type, transcript
                FROM ticket_archives WHERE archive_token = {placeholder}""",
            (token,)
        ).fetchone()

    if not row:
        return "الأرشيف غير موجود.", 404

    transcript_html = html.escape(str(row["transcript"])).replace("\n", "<br>\n")

    return render_template_string("""
    <!doctype html>
    <html lang="ar" dir="rtl">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>أرشيف التكت #{{ number }}</title>
      <style>
        body { font-family: Arial; background:#10121a; color:#f2f2f7; margin:0; padding:24px }
        main { max-width:950px; margin:auto }
        section { background:#1b1e2b; border:1px solid #34384c; border-radius:12px; padding:20px; margin-bottom:16px }
        .transcript { overflow-wrap:anywhere; line-height:1.9 }
        h1 { color:#a99cff }
      </style>
    </head>
    <body><main>
      <h1>أرشيف التكت #{{ number }}</h1>
      <section>
        <p><b>النوع:</b> {{ kind }}</p>
        <p><b>معرّف صاحب التكت:</b> {{ owner }}</p>
        <p><b>الإداري:</b> {{ closer }}</p>
        <p><b>وقت الإغلاق:</b> {{ closed_at }}</p>
        <p>أي شخص يملك رابط الأرشيف يستطيع مشاهدته.</p>
      </section>
      <section class="transcript">{{ transcript_html | safe }}</section>
    </main></body></html>
    """,
        number=str(row["ticket_number"]),
        kind=str(row["ticket_type"]),
        owner=str(row["owner_id"]),
        closer=str(row["closed_by"]),
        closed_at=str(row["closed_at"] or "غير محدد"),
        transcript_html=transcript_html
    )


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "5000")),
        debug=False
    )
