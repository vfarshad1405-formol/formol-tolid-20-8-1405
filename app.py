"""Afraz cloud: authenticated, versioned, shared cost data.
Development: APP_ENV=development DATABASE_URL=sqlite:///... bootstrap credentials required.
Production: PostgreSQL and HTTPS-only cookies are mandatory.
"""
import base64
import hashlib
import hmac
import ipaddress
import json
import math
import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from functools import wraps
from pathlib import Path

from flask import Flask, g, jsonify, redirect, render_template, request, send_file, url_for, make_response
from sqlalchemy import (BigInteger, Boolean, Column, DateTime, ForeignKey, Integer,
                        MetaData, String, Table, Text, create_engine, delete, event,
                        func, insert, select, update)
from sqlalchemy.exc import IntegrityError
from werkzeug.middleware.proxy_fix import ProxyFix

ROOT = Path(__file__).resolve().parent
ENV = os.environ.get('APP_ENV', 'production')
PREVIEW = os.environ.get('ALLOW_PREVIEW_EMBED') == '1' and ENV == 'development'
url = os.environ.get('DATABASE_URL', '')
if url.startswith('postgres://'):
    url = 'postgresql+psycopg://' + url[len('postgres://'):]
elif url.startswith('postgresql://'):
    url = 'postgresql+psycopg://' + url[len('postgresql://'):]
if not url and ENV == 'development':
    url = 'sqlite:///' + str(ROOT / 'dev.sqlite3')
if not url or (ENV != 'development' and not url.startswith('postgresql+psycopg://')):
    raise RuntimeError('Production requires a PostgreSQL DATABASE_URL; SQLite is for development only.')
engine = create_engine(url, pool_pre_ping=True, **({'connect_args': {'check_same_thread': False}} if url.startswith('sqlite:') else {}))
if url.startswith('sqlite:'):
    @event.listens_for(engine, 'connect')
    def _sqlite_fk(dbapi_connection, connection_record):
        dbapi_connection.execute('PRAGMA foreign_keys=ON')

metadata = MetaData()
users = Table('users', metadata,
    Column('id', Integer, primary_key=True, autoincrement=True),
    Column('username', String(80), nullable=False, unique=True),
    Column('password_hash', String(300), nullable=False),
    Column('created_at', DateTime, nullable=False))
sessions = Table('sessions', metadata,
    Column('token_hash', String(64), primary_key=True),
    Column('user_id', Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
    Column('csrf', String(100), nullable=False), Column('expires_at', DateTime, nullable=False))
state = Table('app_state', metadata,
    Column('id', Integer, primary_key=True), Column('revision', BigInteger, nullable=False),
    Column('payload', Text, nullable=False), Column('updated_at', DateTime, nullable=False))
attempts = Table('login_attempts', metadata,
    Column('bucket', String(64), primary_key=True), Column('count', Integer, nullable=False),
    Column('expires_at', DateTime, nullable=False))

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 6 * 1024 * 1024
if os.environ.get('TRUST_PROXY', '0') == '1':
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
COOKIE_SECURE = ENV != 'development' or os.environ.get('COOKIE_SECURE', '0') == '1'
COOKIE_SAMESITE = 'None' if PREVIEW and COOKIE_SECURE else 'Strict'
SESSION_COOKIE = 'afraz_session'
LOGIN_COOKIE = 'afraz_login_nonce'

def now(): return datetime.now(timezone.utc).replace(tzinfo=None)
def digest(s): return hashlib.sha256(s.encode('utf-8')).hexdigest()
def valid_username(s):
    return isinstance(s, str) and 3 <= len(s) <= 50 and bool(re.fullmatch(r'[\w.\-@]+', s, re.UNICODE))
def valid_password(s): return isinstance(s, str) and 12 <= len(s) <= 128

def hash_password(password):
    salt = secrets.token_bytes(16)
    value = hashlib.scrypt(password.encode('utf-8'), salt=salt, n=16384, r=8, p=1, dklen=32)
    return 'scrypt$16384$8$1$' + base64.urlsafe_b64encode(salt).decode() + '$' + base64.urlsafe_b64encode(value).decode()

def verify_password(password, stored):
    try:
        kind, n, r, p, salt, expected = stored.split('$')
        if kind != 'scrypt' or (n, r, p) != ('16384', '8', '1'): return False
        actual = hashlib.scrypt(password.encode('utf-8'), salt=base64.urlsafe_b64decode(salt), n=int(n), r=int(r), p=int(p), dklen=32)
        return hmac.compare_digest(actual, base64.urlsafe_b64decode(expected))
    except (ValueError, TypeError): return False

DUMMY_HASH = hash_password('not-a-real-account-password')

def init_db():
    # One PostgreSQL transaction lock protects schema and bootstrap from worker races.
    with engine.begin() as c:
        if engine.dialect.name == 'postgresql': c.exec_driver_sql('SELECT pg_advisory_xact_lock(721340912)')
        metadata.create_all(c)
        if c.scalar(select(func.count()).select_from(users)) == 0:
            username = os.environ.get('BOOTSTRAP_USER', '')
            password = os.environ.get('BOOTSTRAP_PASSWORD', '')
            if not valid_username(username) or not valid_password(password):
                raise RuntimeError('Set BOOTSTRAP_USER (3-50 characters) and BOOTSTRAP_PASSWORD (12-128 characters) for first startup.')
            c.execute(insert(users).values(username=username, password_hash=hash_password(password), created_at=now()))
        if not c.execute(select(state.c.id).where(state.c.id == 1)).first():
            seed = json.loads((ROOT / 'seed' / 'initial.json').read_text(encoding='utf-8'))
            c.execute(insert(state).values(id=1, revision=1, payload=json.dumps(seed, ensure_ascii=False), updated_at=now()))

init_db()

@app.after_request
def headers(resp):
    resp.headers['Cache-Control'] = 'no-store'
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['Referrer-Policy'] = 'same-origin'
    resp.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    csp = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; base-uri 'self'; form-action 'self'"
    if not PREVIEW:
        csp += "; frame-ancestors 'none'"
        resp.headers['X-Frame-Options'] = 'DENY'
    resp.headers['Content-Security-Policy'] = csp
    if COOKIE_SECURE: resp.headers['Strict-Transport-Security'] = 'max-age=31536000'
    return resp

@app.errorhandler(413)
def too_large(_): return jsonify(error='حجم اطلاعات بیش از حد مجاز است.'), 413


def get_session():
    token = request.cookies.get(SESSION_COOKIE, '')
    if not token or len(token) > 200: return None
    with engine.connect() as c:
        row = c.execute(select(sessions.c.user_id, sessions.c.csrf, users.c.username)
                        .join(users, sessions.c.user_id == users.c.id)
                        .where(sessions.c.token_hash == digest(token), sessions.c.expires_at > now())).mappings().first()
        return dict(row) if row else None

def authenticated(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        g.user = get_session()
        if not g.user:
            return (jsonify(error='نشست پایان یافته است. دوباره وارد شوید.'), 401) if request.path.startswith('/api/') else redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapped

def csrf_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        provided = request.headers.get('X-Afraz-Token', '')
        if not provided or not hmac.compare_digest(provided, g.user['csrf']):
            return jsonify(error='درخواست امنیتی معتبر نیست.'), 403
        return f(*args, **kwargs)
    return wrapped

def attempt_keys(username):
    # Railway's edge provides X-Real-IP. Trust it only when explicitly configured
    # and only when the app is exclusively behind that trusted edge.
    client_ip = request.remote_addr or 'unknown'
    if os.environ.get('RAILWAY_TRUST_REAL_IP', '0') == '1':
        try:
            client_ip = str(ipaddress.ip_address(request.headers.get('X-Real-IP', '')))
        except ValueError:
            pass
    # User and IP buckets are independent to limit broad and targeted guessing.
    return [digest('u:' + username.casefold()), digest('ip:' + client_ip)]

def is_blocked(keys):
    with engine.connect() as c:
        return bool(c.execute(select(attempts.c.bucket).where(attempts.c.bucket.in_(keys), attempts.c.expires_at > now(), attempts.c.count >= 8)).first())

def failed_attempt(keys):
    with engine.begin() as c:
        for key in keys:
            row = c.execute(select(attempts).where(attempts.c.bucket == key).with_for_update()).mappings().first()
            if not row:
                try:
                    with c.begin_nested(): c.execute(insert(attempts).values(bucket=key, count=1, expires_at=now()+timedelta(minutes=15)))
                except IntegrityError:
                    c.execute(update(attempts).where(attempts.c.bucket==key).values(count=attempts.c.count+1))
            elif row['expires_at'] <= now(): c.execute(update(attempts).where(attempts.c.bucket == key).values(count=1, expires_at=now()+timedelta(minutes=15)))
            else: c.execute(update(attempts).where(attempts.c.bucket == key).values(count=attempts.c.count+1))

def login_response(message='', status=200):
    nonce = secrets.token_urlsafe(32)
    resp = make_response(render_template('login.html', error=message, nonce=nonce), status)
    resp.set_cookie(LOGIN_COOKIE, nonce, secure=COOKIE_SECURE, httponly=True, samesite=COOKIE_SAMESITE, max_age=600)
    return resp

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        if get_session(): return redirect('/')
        return login_response()
    cookie = request.cookies.get(LOGIN_COOKIE, '')
    submitted = request.form.get('nonce', '')
    if not cookie or not submitted or not hmac.compare_digest(cookie, submitted): return login_response('فرم منقضی شده است؛ دوباره تلاش کنید.', 403)
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    if len(username) > 80 or len(password) > 128: return login_response('نام کاربری یا گذرواژه نادرست است.', 400)
    keys = attempt_keys(username)
    if is_blocked(keys): return login_response('تعداد تلاش‌ها زیاد بوده است. ۱۵ دقیقه بعد دوباره تلاش کنید.', 429)
    with engine.connect() as c: row = c.execute(select(users).where(users.c.username == username)).mappings().first()
    good = verify_password(password, row['password_hash'] if row else DUMMY_HASH)
    if not row or not good:
        failed_attempt(keys)
        return login_response('نام کاربری یا گذرواژه نادرست است.', 401)
    token, csrf = secrets.token_urlsafe(48), secrets.token_urlsafe(32)
    with engine.begin() as c:
        c.execute(delete(attempts).where(attempts.c.bucket.in_(keys)))
        c.execute(delete(sessions).where(sessions.c.expires_at <= now()))
        c.execute(insert(sessions).values(token_hash=digest(token), user_id=row['id'], csrf=csrf, expires_at=now()+timedelta(hours=12)))
    resp = redirect('/')
    resp.set_cookie(SESSION_COOKIE, token, secure=COOKIE_SECURE, httponly=True, samesite=COOKIE_SAMESITE, max_age=12*3600, path='/')
    resp.delete_cookie(LOGIN_COOKIE, path='/')
    return resp

@app.get('/')
@authenticated
def home(): return send_file(ROOT / 'templates' / 'app.html', mimetype='text/html')

@app.get('/api/session')
@authenticated
def session_info(): return jsonify(username=g.user['username'], userId=g.user['user_id'], csrf=g.user['csrf'])

@app.post('/api/logout')
@authenticated
@csrf_required
def logout():
    with engine.begin() as c: c.execute(delete(sessions).where(sessions.c.token_hash == digest(request.cookies.get(SESSION_COOKIE, ''))))
    resp = jsonify(ok=True)
    resp.delete_cookie(SESSION_COOKIE, path='/', secure=COOKIE_SECURE, httponly=True, samesite=COOKIE_SAMESITE)
    return resp

@app.get('/api/data')
@authenticated
def get_data():
    with engine.connect() as c: row = c.execute(select(state.c.payload, state.c.revision).where(state.c.id == 1)).first()
    resp = app.response_class(row.payload, mimetype='application/json')
    resp.headers['X-Revision'] = str(row.revision)
    return resp


def valid_number(v, maximum=100000000000):
    if isinstance(v, bool) or not isinstance(v, (int, float)) or v < 0 or v > maximum or not math.isfinite(v): return False
    try: return Decimal(str(v)).as_tuple().exponent >= -6
    except (InvalidOperation, ValueError): return False

def bounded_string(v, limit=500): return isinstance(v, str) and len(v) <= limit

def validate_data(d):
    if not isinstance(d, dict) or d.get('version') != 1 or not isinstance(d.get('settings'), dict): return 'ساختار اطلاعات معتبر نیست.'
    settings=d['settings']
    if not bounded_string(settings.get('company',''),200) or not bounded_string(settings.get('warning',''),1000) or not valid_number(settings.get('priceListMarkup',20),1000000): return 'تنظیمات معتبر نیست.'
    arrays = [d.get('resources'), d.get('recipes'), d.get('products')]
    if any(not isinstance(x, list) for x in arrays) or any(len(x) > 10000 for x in arrays): return 'فهرست اطلاعات معتبر نیست.'
    ids = set()
    for r in d['resources']:
        if not isinstance(r, dict) or not bounded_string(r.get('id'), 128) or not r['id'] or r['id'] in ids or not bounded_string(r.get('name')) or not r['name']: return 'قلم یا شناسه آن معتبر نیست.'
        ids.add(r['id'])
        if any(not bounded_string(r.get(k,''),500) for k in ['code','category','vendor','date','note']) or not isinstance(r.get('zeroConfirmed',False),bool): return 'مشخصات قلم معتبر نیست.'
        if r.get('unit') not in ['عدد','کیلوگرم','گرم','متر','ساعت','بسته','لیتر','دست','سرویس'] or r.get('adjustmentType') not in ['افزایش','کاهش']: return 'واحد یا تعدیل قلم معتبر نیست.'
        if not all(valid_number(r.get(k, 0)) for k in ['price','adjustment','quantity']) or (r['adjustmentType']=='کاهش' and r.get('adjustment',0)>100): return 'مقادیر عددی قلم معتبر نیست.'
    rids = set()
    for r in d['recipes']:
        if not isinstance(r,dict) or not bounded_string(r.get('id'),128) or not r['id'] or r['id'] in rids or not bounded_string(r.get('name')) or not r['name']: return 'فرمول یا شناسه آن معتبر نیست.'
        rids.add(r['id'])
        if any(not bounded_string(r.get(k,''),2000) for k in ['code','note','sourceFeeCell','sourceFeeFormula']) or not isinstance(r.get('feeDefined',False),bool): return 'مشخصات فرمول معتبر نیست.'
        if not all(valid_number(r.get(k,0)) for k in ['yield','overhead','factoryMarkup']) or r.get('yield',0)<=0 or not isinstance(r.get('components'),list) or len(r['components'])>5000: return 'مقادیر فرمول معتبر نیست.'
        component_ids=set()
        for c in r['components']:
            if not isinstance(c,dict) or not bounded_string(c.get('id'),128) or not c.get('id') or c['id'] in component_ids or not bounded_string(c.get('resourceId'),128) or c['resourceId'] not in ids or not valid_number(c.get('qty')) or not valid_number(c.get('waste')) or not isinstance(c.get('feeSelected',False),bool): return 'جزء فرمول یا ارتباط آن معتبر نیست.'
            component_ids.add(c['id'])
    pids=set(); codes=set()
    for p in d['products']:
        if not isinstance(p,dict) or not bounded_string(p.get('id'),128) or not p['id'] or p['id'] in pids or not bounded_string(p.get('name')) or not p['name'] or not bounded_string(p.get('code'),128) or not p['code'] or p['code'] in codes: return 'محصول یا کد آن معتبر نیست.'
        pids.add(p['id']); codes.add(p['code'])
        if not bounded_string(p.get('recipeId',''),128) or (p.get('recipeId') and p['recipeId'] not in rids) or not bounded_string(p.get('note',''),2000) or not isinstance(p.get('available'),bool): return 'ارتباط فرمول محصول معتبر نیست.'
        if not all(valid_number(p.get(k,0)) for k in ['multiplier','marketMarkup','listPrice','discount','priceMarkup']) or p.get('multiplier',0)<=0 or p.get('discount',0)>100 or p.get('priceMarkup',0)>1000000: return 'مقادیر محصول معتبر نیست.'
    if not isinstance(d.get('audit',[]),list) or len(d.get('audit',[]))>500: return 'فهرست تغییرات معتبر نیست.'
    return None

@app.post('/api/data')
@authenticated
@csrf_required
def put_data():
    try: revision = int(request.headers.get('X-Revision',''))
    except ValueError: return jsonify(error='شماره نسخه اطلاعات معتبر نیست.'), 400
    d = request.get_json(silent=True)
    error = validate_data(d)
    if error: return jsonify(error=error), 400
    if d.get('audit') and isinstance(d['audit'][0],dict): d['audit'][0]['actor'] = g.user['username']
    payload = json.dumps(d, ensure_ascii=False, allow_nan=False, separators=(',', ':'))
    with engine.begin() as c:
        result = c.execute(update(state).where(state.c.id==1, state.c.revision==revision).values(payload=payload, revision=state.c.revision+1, updated_at=now()))
        if result.rowcount != 1: return jsonify(error='اطلاعات توسط کاربر دیگری تغییر کرده است. تغییر شما ذخیره نشد.'), 409
    resp = jsonify(ok=True)
    resp.headers['X-Revision'] = str(revision+1)
    return resp

@app.get('/api/users')
@authenticated
def list_users():
    with engine.connect() as c: rows = c.execute(select(users.c.id, users.c.username, users.c.created_at).order_by(users.c.id)).mappings().all()
    return jsonify(users=[{'id':r['id'],'username':r['username'],'createdAt':r['created_at'].isoformat()} for r in rows], currentId=g.user['user_id'])

@app.post('/api/users')
@authenticated
@csrf_required
def create_user():
    d=request.get_json(silent=True) or {}; username=d.get('username','').strip() if isinstance(d.get('username'),str) else ''; password=d.get('password','')
    if not valid_username(username) or not valid_password(password): return jsonify(error='نام کاربری ۳ تا ۵۰ نویسه و گذرواژه ۱۲ تا ۱۲۸ نویسه لازم است.'), 400
    try:
        with engine.begin() as c: c.execute(insert(users).values(username=username,password_hash=hash_password(password),created_at=now()))
    except IntegrityError: return jsonify(error='این نام کاربری قبلاً ثبت شده است.'), 409
    return jsonify(ok=True), 201

@app.delete('/api/users/<int:user_id>')
@authenticated
@csrf_required
def remove_user(user_id):
    if user_id == g.user['user_id']: return jsonify(error='حذف حسابی که اکنون با آن وارد شده‌اید مجاز نیست.'), 400
    with engine.begin() as c:
        result=c.execute(delete(users).where(users.c.id==user_id))
    if not result.rowcount: return jsonify(error='کاربر پیدا نشد.'),404
    return jsonify(ok=True)

@app.post('/api/password')
@authenticated
@csrf_required
def change_password():
    d = request.get_json(silent=True) or {}
    old = d.get('currentPassword', '')
    new = d.get('newPassword', '')
    if not isinstance(old, str) or not valid_password(new): return jsonify(error='گذرواژه جدید باید ۱۲ تا ۱۲۸ نویسه داشته باشد.'), 400
    with engine.begin() as c:
        row = c.execute(select(users.c.password_hash).where(users.c.id==g.user['user_id']).with_for_update()).first()
        if not row or not verify_password(old, row.password_hash): return jsonify(error='گذرواژه فعلی نادرست است.'), 403
        c.execute(update(users).where(users.c.id==g.user['user_id']).values(password_hash=hash_password(new)))
        current_hash = digest(request.cookies.get(SESSION_COOKIE, ''))
        c.execute(delete(sessions).where(sessions.c.user_id==g.user['user_id'], sessions.c.token_hash!=current_hash))
    return jsonify(ok=True)

@app.get('/healthz')
def health():
    try:
        with engine.connect() as c: c.execute(select(1))
        return jsonify(status='ok')
    except Exception: return jsonify(status='error'), 503

if __name__ == '__main__':
    if ENV != 'development': raise RuntimeError('Use a production WSGI server (e.g. gunicorn).')
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT','5000')), debug=False)
