"""Starter Flask backend for a Discord ticket dashboard.
Deploy with HTTPS and environment variables. Never commit secrets.
"""
import os, json, secrets, sqlite3
from functools import wraps
from flask import Flask, jsonify, request, session, redirect, url_for, render_template

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'dev-only-change-me')
DB_PATH = os.environ.get('DB_PATH', 'dashboard.sqlite3')
DISCORD_CLIENT_ID = os.environ.get('DISCORD_CLIENT_ID', '')
DISCORD_CLIENT_SECRET = os.environ.get('DISCORD_CLIENT_SECRET', '')
DISCORD_REDIRECT_URI = os.environ.get('DISCORD_REDIRECT_URI', '')
DASHBOARD_API_KEY = os.environ.get('DASHBOARD_API_KEY', '')

DEFAULT_CONFIG = {
  'panel': {'title':'مركز الدعم الفني','description':'مرحبًا بك! اختر القسم المناسب من القائمة أدناه لفتح تذكرة جديدة.','button_label':'فتح تذكرة','color':'#7865f5'},
  'behavior': {'one_ticket_per_user':True,'welcome_message_enabled':True,'transcript_enabled':False},
  'channels': {'log_channel_id':'','ticket_category_id':'','panel_channel_id':''},
  'points': {'single_point_per_ticket':True,'staff_logs_enabled':True},
  'messages': {'welcome':'أهلًا بك {user}، وضّح طلبك وسيقوم فريق الدعم بمساعدتك قريبًا.','close':'تم إغلاق التذكرة بواسطة {staff}.'},
  'categories': [{'name':'الدعم الفني','desc':'مساعدة في المشاكل التقنية','active':True},{'name':'الاستفسارات العامة','desc':'أسئلة واستفسارات','active':True},{'name':'الشكاوى والاقتراحات','desc':'أرسل ملاحظتك للإدارة','active':True}],
  'staff': []
}

def db():
    con=sqlite3.connect(DB_PATH); con.row_factory=sqlite3.Row
    con.execute('CREATE TABLE IF NOT EXISTS configs (guild_id TEXT PRIMARY KEY, config_json TEXT NOT NULL, updated_at TEXT DEFAULT CURRENT_TIMESTAMP)')
    return con

def require_login(fn):
    @wraps(fn)
    def wrapped(*args,**kwargs):
        if not session.get('discord_user_id'):
            return jsonify({'error':'login_required'}),401
        return fn(*args,**kwargs)
    return wrapped

@app.get('/')
def index():
    return render_template('index.html')

@app.get('/health')
def health():
    return jsonify({'ok':True,'service':'ticket-dashboard'})

@app.get('/login')
def login():
    if not (DISCORD_CLIENT_ID and DISCORD_REDIRECT_URI):
        return 'Discord OAuth is not configured. Set DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET, and DISCORD_REDIRECT_URI.', 503
    from urllib.parse import urlencode
    state=secrets.token_urlsafe(24); session['oauth_state']=state
    params={'client_id':DISCORD_CLIENT_ID,'redirect_uri':DISCORD_REDIRECT_URI,'response_type':'code','scope':'identify guilds','state':state,'prompt':'consent'}
    return redirect('https://discord.com/oauth2/authorize?'+urlencode(params))

@app.get('/oauth/callback')
def oauth_callback():
    # Intentionally fail closed until OAuth token exchange + guild permission verification are configured.
    if not DISCORD_CLIENT_SECRET:
        return 'Discord OAuth is not configured on the server.', 503
    if request.args.get('state') != session.pop('oauth_state',None):
        return 'Invalid OAuth state. Please retry login.', 400
    code=request.args.get('code')
    if not code: return 'Missing authorization code.',400
    # TODO production integration: exchange code with Discord, fetch /users/@me and /users/@me/guilds,
    # store user id and guilds, then allow only guilds where user has MANAGE_GUILD or ADMINISTRATOR.
    return 'OAuth callback reached. Complete Discord token exchange and guild permission checks before enabling dashboard writes.', 501

@app.get('/api/config')
@require_login
def get_config():
    guild_id=request.args.get('guild_id','default')
    with db() as con:
        row=con.execute('SELECT config_json FROM configs WHERE guild_id=?',(guild_id,)).fetchone()
    return jsonify({'guild_id':guild_id,'config':json.loads(row['config_json']) if row else DEFAULT_CONFIG})

@app.put('/api/config')
@require_login
def put_config():
    payload=request.get_json(silent=True)
    if not isinstance(payload,dict): return jsonify({'error':'invalid_json'}),400
    # Production TODO: validate that the logged-in user manages the selected guild.
    guild_id=str(payload.pop('guild_id','default'))
    data=json.dumps(payload,ensure_ascii=False)
    with db() as con:
        con.execute('INSERT INTO configs(guild_id,config_json,updated_at) VALUES(?,?,CURRENT_TIMESTAMP) ON CONFLICT(guild_id) DO UPDATE SET config_json=excluded.config_json,updated_at=CURRENT_TIMESTAMP',(guild_id,data))
    return jsonify({'ok':True,'guild_id':guild_id})

@app.get('/api/bot/config')
def bot_config():
    key=request.headers.get('X-Dashboard-Key','')
    if not DASHBOARD_API_KEY or not secrets.compare_digest(key,DASHBOARD_API_KEY):
        return jsonify({'error':'unauthorized'}),401
    guild_id=request.args.get('guild_id','default')
    with db() as con:
        row=con.execute('SELECT config_json,updated_at FROM configs WHERE guild_id=?',(guild_id,)).fetchone()
    return jsonify({'guild_id':guild_id,'config':json.loads(row['config_json']) if row else DEFAULT_CONFIG,'updated_at':row['updated_at'] if row else None})

if __name__=='__main__':
    app.run(host='0.0.0.0',port=int(os.environ.get('PORT','5000')),debug=False)
