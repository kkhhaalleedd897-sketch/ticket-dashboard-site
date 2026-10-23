
"""Flask backend for a Discord ticket dashboard."""
import os
import json
import secrets
import sqlite3
import html
from functools import wraps
from flask import (
    Flask, jsonify, request, session, redirect,
    render_template, render_template_string, url_for
)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-only-change-me")

DATABASE_URL = os.environ.get("DATABASE_URL", "")
DB_PATH = os.environ.get("DB_PATH", "dashboard.sqlite3")
DASHBOARD_API_KEY = os.environ.get("DASHBOARD_API_KEY", "")

DISCORD_CLIENT_ID = os.environ.get("DISCORD_CLIENT_ID", "")
DISCORD_CLIENT_SECRET = os.environ.get("DISCORD_CLIENT_SECRET", "")
DISCORD_REDIRECT_URI = os.environ.get("DISCORD_REDIRECT_URI", "")

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


def require_login(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
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


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/health")
def health():
    return jsonify({"ok": True, "service": "ticket-dashboard"})


@app.get("/login")
def login():
    if not (DISCORD_CLIENT_ID and DISCORD_REDIRECT_URI):
        return "Discord OAuth is not configured.", 503

    from urllib.parse import urlencode
    state = secrets.token_urlsafe(24)
    session["oauth_state"] = state

    params = {
        "client_id": DISCORD_CLIENT_ID,
        "redirect_uri": DISCORD_REDIRECT_URI,
        "response_type": "code",
        "scope": "identify guilds",
        "state": state
    }
    return redirect("https://discord.com/oauth2/authorize?" + urlencode(params))


@app.get("/oauth/callback")
def oauth_callback():
    # Discord OAuth is not fully implemented yet.
    if not DISCORD_CLIENT_SECRET:
        return "Discord OAuth is not configured on the server.", 503

    if request.args.get("state") != session.pop("oauth_state", None):
        return "Invalid OAuth state. Please retry login.", 400

    if not request.args.get("code"):
        return "Missing authorization code.", 400

    return "Discord OAuth setup is incomplete.", 501


@app.get("/api/config")
@require_login
def get_config():
    guild_id = request.args.get("guild_id", "default")
    with db() as con:
        row = con.execute(
            "SELECT config_json FROM configs WHERE guild_id = %s" if DATABASE_URL
            else "SELECT config_json FROM configs WHERE guild_id = ?",
            (guild_id,)
        ).fetchone()

    config_json = row["config_json"] if row else None
    return jsonify({
        "guild_id": guild_id,
        "config": json.loads(config_json) if config_json else DEFAULT_CONFIG
    })


@app.put("/api/config")
@require_login
def put_config():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "invalid_json"}), 400

    payload = payload.copy()
    guild_id = str(payload.pop("guild_id", "default"))
    data = json.dumps(payload, ensure_ascii=False)

    sql = """
        INSERT INTO configs (guild_id, config_json, updated_at)
        VALUES (%s, %s, CURRENT_TIMESTAMP)
        ON CONFLICT (guild_id) DO UPDATE SET
        config_json = EXCLUDED.config_json,
        updated_at = CURRENT_TIMESTAMP
    """ if DATABASE_URL else """
        INSERT INTO configs (guild_id, config_json, updated_at)
        VALUES (?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(guild_id) DO UPDATE SET
        config_json=excluded.config_json,
        updated_at=CURRENT_TIMESTAMP
    """

    with db() as con:
        con.execute(sql, (guild_id, data))

    return jsonify({"ok": True, "guild_id": guild_id})


@app.get("/api/bot/config")
def bot_config():
    if not valid_bot_key():
        return jsonify({"error": "unauthorized"}), 401

    guild_id = request.args.get("guild_id", "default")
    sql = (
        "SELECT config_json, updated_at FROM configs WHERE guild_id = %s"
        if DATABASE_URL
        else "SELECT config_json, updated_at FROM configs WHERE guild_id = ?"
    )

    with db() as con:
        row = con.execute(sql, (guild_id,)).fetchone()

    config_json = row["config_json"] if row else None
    return jsonify({
        "guild_id": guild_id,
        "config": json.loads(config_json) if config_json else DEFAULT_CONFIG,
        "updated_at": str(row["updated_at"]) if row else None
    })


@app.post("/api/bot/archive")
def receive_archive():
    """Accept ticket transcripts only from the bot using the shared secret."""
    if not valid_bot_key():
        return jsonify({"error": "unauthorized"}), 401

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "invalid_json"}), 400

    required = (
        "guild_id", "channel_id", "ticket_number", "owner_id",
        "closed_by", "ticket_type", "transcript"
    )
    if any(payload.get(key) is None for key in required):
        return jsonify({"error": "missing_fields", "required": required}), 400

    # IDs are stored as strings to avoid integer-size and database differences.
    values = {
        key: str(payload[key]).strip()
        for key in (
            "guild_id", "channel_id", "ticket_number", "owner_id",
            "closed_by", "ticket_type"
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

    # Repeated submissions for the same channel reuse its existing archive token.
    with db() as con:
        placeholder = "%s" if DATABASE_URL else "?"
        row = con.execute(
            f"SELECT archive_token FROM ticket_archives WHERE channel_id = {placeholder}",
            (values["channel_id"],)
        ).fetchone()

        if row:
            archive_token = row["archive_token"]
            update_sql = """
                UPDATE ticket_archives SET
                    guild_id = %s, ticket_number = %s, owner_id = %s,
                    closed_by = %s, closed_at = %s, ticket_type = %s,
                    transcript = %s
                WHERE channel_id = %s
            """ if DATABASE_URL else """
                UPDATE ticket_archives SET
                    guild_id = ?, ticket_number = ?, owner_id = ?,
                    closed_by = ?, closed_at = ?, ticket_type = ?,
                    transcript = ?
                WHERE channel_id = ?
            """
            con.execute(update_sql, (
                values["guild_id"], values["ticket_number"],
                values["owner_id"], values["closed_by"], closed_at,
                values["ticket_type"], transcript, values["channel_id"]
            ))
        else:
            archive_token = secrets.token_urlsafe(32)
            insert_sql = """
                INSERT INTO ticket_archives (
                    channel_id, archive_token, guild_id, ticket_number,
                    owner_id, closed_by, closed_at, ticket_type, transcript
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """ if DATABASE_URL else """
                INSERT INTO ticket_archives (
                    channel_id, archive_token, guild_id, ticket_number,
                    owner_id, closed_by, closed_at, ticket_type, transcript
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
            con.execute(insert_sql, (
                values["channel_id"], archive_token, values["guild_id"],
                values["ticket_number"], values["owner_id"],
                values["closed_by"], closed_at, values["ticket_type"],
                transcript
            ))

    return jsonify({
        "ok": True,
        "archive_url": url_for(
            "view_archive", token=archive_token, _external=True
        )
    }), 201


@app.get("/archive/<token>")
def view_archive(token):
    """An unguessable bearer link; anyone who has the URL can read this archive."""
    with db() as con:
        placeholder = "%s" if DATABASE_URL else "?"
        row = con.execute(
            f"""
            SELECT guild_id, ticket_number, owner_id, closed_by,
                   closed_at, ticket_type, transcript, created_at
            FROM ticket_archives WHERE archive_token = {placeholder}
            """,
            (token,)
        ).fetchone()

    if not row:
        return "الأرشيف غير موجود.", 404

    transcript_html = html.escape(row["transcript"]).replace("\n", "<br>\n")
    ticket_number = html.escape(str(row["ticket_number"]))
    ticket_type = html.escape(str(row["ticket_type"]))
    owner_id = html.escape(str(row["owner_id"]))
    closed_by = html.escape(str(row["closed_by"]))
    closed_at = html.escape(str(row["closed_at"] or "غير محدد"))

    return render_template_string("""
    <!doctype html>
    <html lang="ar" dir="rtl">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>أرشيف التكت #{{ number }}</title>
      <style>
        body { font-family: Arial, sans-serif; background:#10121a; color:#f2f2f7;
               margin:0; padding:24px; }
        main { max-width:950px; margin:auto; }
        section { background:#1b1e2b; border:1px solid #34384c;
                  border-radius:12px; padding:20px; margin-bottom:16px; }
        .transcript { white-space:normal; overflow-wrap:anywhere;
                      line-height:1.9; }
        h1 { color:#a99cff; }
        .warning { color:#ffcf70; }
      </style>
    </head>
    <body><main>
      <h1>أرشيف التكت #{{ number }}</h1>
      <section>
        <p><b>النوع:</b> {{ ticket_type }}</p>
        <p><b>معرّف صاحب التكت:</b> {{ owner }}</p>
        <p><b>أغلقه:</b> {{ closer }}</p>
        <p><b>وقت الإغلاق:</b> {{ closed_at }}</p>
        <p class="warning">تنبيه: هذا رابط خاص؛ أي شخص يملك الرابط يستطيع مشاهدة الأرشيف.</p>
      </section>
      <section class="transcript">{{ transcript_html | safe }}</section>
    </main></body></html>
    """, number=ticket_number, ticket_type=ticket_type,
       owner=owner_id, closer=closed_by, closed_at=closed_at,
       transcript_html=transcript_html)


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "5000")),
        debug=False
    )
