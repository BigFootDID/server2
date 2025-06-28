from flask import Flask, request, jsonify, abort, session, render_template, send_file
import os, io, json, time, base64, subprocess
from datetime import datetime, timedelta
from functools import wraps
from hashlib import sha256
from threading import Lock
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
import hmac

# --- Git Repository 설정 방법 ---
# 1. 원격 저장소를 GitHub/GitLab 등에서 사전에 생성하세요.
# 2. Render 환경 변수에 아래 값 설정:
#    GIT_REMOTE_URL=https://github.com/<username>/<repo>.git
#    (옵션) GIT_USER_NAME="Auto Commit Bot"
#    (옵션) GIT_USER_EMAIL="bot@example.com"

app = Flask(__name__, template_folder='templates')
app.secret_key = os.getenv('FLASK_SECRET_KEY') or 'secret'
app.permanent_session_lifetime = timedelta(hours=1)

BASE = os.path.dirname(__file__)
GIT_REPO_DIR = BASE
GIT_REMOTE_URL = os.getenv('GIT_REMOTE_URL')
GIT_USER_NAME = os.getenv('GIT_USER_NAME', 'Auto Commit Bot')
GIT_USER_EMAIL = os.getenv('GIT_USER_EMAIL', 'bot@example.com')
UPLOAD_DIR = os.path.join(BASE, 'uploads')
SIGNED_DIR = os.path.join(BASE, 'signed')
STORAGE = os.path.join(BASE, 'submissions.json')
ADMIN_FILE = os.path.join(BASE, 'admin_users.json')
HISTORY = os.path.join(BASE, 'signed_history.json')
INITIAL_BULK = os.path.join(BASE, 'bulk_submit.txt')
SECRET = os.getenv('APP_SECRET','supersecret')
LOG_CRED_FILE = os.path.join(BASE, 'credentials.log')
INSTALLER_PATH = os.path.join(BASE, "Installer.exe")
VERSION_PATH = os.path.join(BASE, "latest_version.txt")

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(SIGNED_DIR, exist_ok=True)
LOCK = Lock()
BLACK, REQ = {}, {}
# Fixed-window rate limit parameters
MAX, WINDOW, BLOCK = 60, 60, 30  # requests, seconds, block duration

# Token Bucket parameters for all endpoints
TOKEN_BUCKET = {}
TB_CAPACITY = 50      # max tokens per IP
TB_FILL_RATE = 3   # tokens replenished per second

# Git helpers omitted for brevity (unchanged)
def run_git(*args, check=True): return subprocess.run(['git', '-C', GIT_REPO_DIR] + list(args), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=check)
def git_init_and_remote():
    git_dir = os.path.join(GIT_REPO_DIR, '.git')
    if not os.path.exists(git_dir): run_git('init'); run_git('checkout', '-b', 'main')
    if GIT_REMOTE_URL:
        try: run_git('remote', 'add', 'origin', GIT_REMOTE_URL)
        except: run_git('remote', 'set-url', 'origin', GIT_REMOTE_URL)
    run_git('config','user.name',GIT_USER_NAME); run_git('config','user.email',GIT_USER_EMAIL)
def git_pull():
    if GIT_REMOTE_URL:
        try: run_git('fetch','origin',check=False); run_git('merge','origin/main','--allow-unrelated-histories',check=False)
        except: pass
def git_commit_and_push(msg):
    try: run_git('add','.'); run_git('commit','-m',msg); run_git('push','origin','main','--set-upstream')
    except subprocess.CalledProcessError as e:
        if 'set-upstream' in e.stderr.decode(): run_git('push','origin','main',check=False)
def git_track(msg):
    def deco(f):
        @wraps(f)
        def w(*a,**k): res=f(*a,**k); git_commit_and_push(msg); return res
        return w
    return deco
# Initialization
try: git_init_and_remote(); git_pull(); git_commit_and_push('Initialize repository')
except: pass
    
def save_signed_history(entry):
    signed_history.append(entry)
    json.dump(signed_history, open(HISTORY, 'w'), indent=2)
# Utility functions

def ip():
    xff=request.headers.get('X-Forwarded-For','')
    return xff.split(',')[0] if xff else request.remote_addr

def admin_required(f):
    @wraps(f)
    def d(*a,**k):
        if not session.get('is_admin'): abort(403)
        return f(*a,**k)
    return d
    
def require_app(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        sig = request.headers.get('X-Signature','')
        body = request.get_data() or b''
        expected = hmac.new(SECRET.encode(), body, sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            abort(403)
        return f(*args, **kwargs)
    return wrapper

# Data loading
if os.path.exists(ADMIN_FILE): admin_users=json.load(open(ADMIN_FILE))
else:
    admin_users={'admin':sha256('thsehddlr'.encode()).hexdigest()}
    json.dump(admin_users,open(ADMIN_FILE,'w'),indent=2)
    git_commit_and_push('Init admin_users')
submissions=json.load(open(STORAGE,'r')) if os.path.exists(STORAGE) else {}
signed_history=json.load(open(HISTORY,'r')) if os.path.exists(HISTORY) else []
# --- If submissions.json is empty but bulk_submit.txt exists, restore from it ---
if not submissions and os.path.exists(INITIAL_BULK):
    try:
        with open(INITIAL_BULK, 'r', encoding='utf-8') as f:
            encoded = f.read()
        decoded = base64.b64decode(encoded).decode('utf-8')
        lines = decoded.splitlines()
        new_subs = {}
        temp = None
        buf = []
        now = datetime.utcnow().isoformat()
        client = 'auto-recovered'
        for line in lines:
            s = line.rstrip()
            if s.endswith('~') and temp is None:
                temp = s[:-1].strip()
                buf = []
            elif s.endswith('~') and temp:
                new_subs[temp] = {
                    'code': '\n'.join(buf),
                    'updated_at': now,
                    'uploader_ip': client
                }
                temp = None
            elif temp:
                buf.append(line)  # 원본 그대로 append
        submissions.update(new_subs)
        json.dump(submissions, open(STORAGE, 'w'), indent=2)
        git_commit_and_push("Recovered submissions from bulk_submit.txt")
    except Exception as e:
        print(f"[WARN] Failed to recover from bulk_submit.txt: {e}")

# Global rate limit for all endpoints
@app.before_request
def global_rate_limit():
    # require_app 인증된 요청은 예외
    sig = request.headers.get('X-Signature', '')
    body = request.get_data() or b''
    expected = hmac.new(SECRET.encode(), body, sha256).hexdigest()
    if hmac.compare_digest(sig, expected):
        return  # 통과

    # 이하 기존 로직
    client, now = ip(), time.time()
    BLACK.update({ip: exp for ip, exp in BLACK.items() if exp > now})
    if client in BLACK: abort(429)

    bucket = TOKEN_BUCKET.setdefault(client, {'tokens': TB_CAPACITY, 'last': now})
    delta = now - bucket['last']
    bucket['tokens'] = min(TB_CAPACITY, bucket['tokens'] + delta * TB_FILL_RATE)
    bucket['last'] = now
    if bucket['tokens'] < 1:
        BLACK[client] = now + BLOCK
        abort(429)
    bucket['tokens'] -= 1

    REQ.setdefault(client, []).append(now)
    REQ[client] = [t for t in REQ[client] if now - t <= WINDOW]
    if len(REQ[client]) > MAX:
        BLACK[client] = now + BLOCK
        abort(429)

def save_bulk_from_submissions():
    lines = []
    for pid in sorted(submissions.keys()):
        code = submissions[pid]['code']
        lines.append(f"{pid}~\n{code}\n~\n")
    raw = ''.join(lines)
    encoded = base64.b64encode(raw.encode('utf-8')).decode()
    with open(INITIAL_BULK, 'w', encoding='utf-8') as f:
        f.write(encoded)

# Views & Endpoints (decorators unchanged)
@app.route('/')
def index(): return render_template('index.html')
@app.route('/upload.html')
def page_upload(): return render_template('upload.html')
@app.route('/license.html')
def page_license(): return render_template('license.html')
@app.route('/admin.html')
@admin_required
def page_admin(): return render_template('admin.html')

# --- Bulk submit upload ---
@app.route('/upload', methods=['POST'])
@git_track("update bulk submissions")
@require_app
def upload_bulk():
    if 'file' not in request.files:
        return jsonify(error='No file'), 400
    f = request.files['file']
    fn = secure_filename(f.filename)
    if not fn.endswith('.txt'):
        return jsonify(error='Only .txt'), 400

    content = f.read().decode('utf-8')
    lines = content.splitlines()
    now_iso = datetime.utcnow().isoformat()
    client = ip()

    # decode된 내용 정리
    new = {}
    temp = None
    buf = []
    for line in lines:
        s = line.strip()
        if s.endswith('~') and temp is None:
            temp = s[:-1].strip()
            buf = []
        elif s.endswith('~') and temp:
            new[temp] = {'code': '\n'.join(buf), 'updated_at': now_iso, 'uploader_ip': client}
            temp = None
        elif temp:
            buf.append(line)

    # 기존 submissions에 merge (기존 항목은 덮어씀)
    updated = 0
    for pid, entry in new.items():
        if pid not in submissions or submissions[pid]['code'] != entry['code']:
            submissions[pid] = entry
            updated += 1

    # 저장
    json.dump(submissions, open(STORAGE, 'w'), indent=2)
    save_bulk_from_submissions()

    return jsonify(status='ok', updated=updated, total=len(submissions))


# --- Bulk download public ---
@app.route('/download_bulk_submit', methods=['GET'])
@require_app
def download_bulk_submit():
     """
     Public endpoint: returns JSON containing base64-encoded bulk_submit content.
     """
     if not os.path.exists(INITIAL_BULK):
         return jsonify(error='bulk not found'), 404
     # INITIAL_BULK already contains base64-encoded lines
     with open(INITIAL_BULK, 'r', encoding='utf-8') as f:
         content_b64 = f.read().strip()
     return jsonify(
         filename='bulk_submit.txt.b64',
         content_b64=content_b64
     )

# --- Bulk download admin ---
@app.route('/admin/download_bulk_submit', methods=['GET'])
@admin_required
@git_track("admin downloaded bulk")
def admin_download_bulk_submit():
     """
     Admin endpoint: returns the same JSON as public, but only accessible by admin.
     """
     # reuse public logic
     return download_bulk_submit()
@app.route('/admin/download_bulk_submit')
@admin_required
@git_track("admin downloaded bulk")
def download_admin():
    if not os.path.exists(INITIAL_BULK):
        return jsonify(error='no bulk file'), 404

    with open(INITIAL_BULK, 'r', encoding='utf-8') as f:
        encoded = f.read().strip()
    try:
        decoded = base64.b64decode(encoded).decode('utf-8')
    except:
        return jsonify(error='decoding failed'), 500

    buf = io.BytesIO(decoded.encode())
    buf.seek(0)
    return send_file(buf, as_attachment=True, download_name='bulk_submit.txt')

# --- Admin clear submissions ---
@app.route('/admin/clear', methods=['POST'])
@admin_required
@git_track("cleared submissions")
def clear_subs():
    submissions.clear(); json.dump(submissions, open(STORAGE,'w'), indent=2)
    save_bulk_from_submissions()
    return jsonify(status='cleared')

# --- License upload ---
@app.route('/upload_license', methods=['POST'])
@git_track("save .lic.request")
@require_app
def upload_license():
    if 'file' not in request.files:
        return jsonify(error='No file'), 400
    raw = request.files['file'].read().decode().strip()
    try:
        info = json.loads(base64.b64decode(raw.encode()).decode())
        uid = info.get('id','unknown'); hwid = info.get('hwid','')
    except:
        return jsonify(error='Invalid payload'), 400
    for ex in os.listdir(UPLOAD_DIR):
        if ex.startswith(f"{uid}_") and time.time()-os.path.getmtime(os.path.join(UPLOAD_DIR,ex))<WINDOW:
            return jsonify(error='Retry later'), 429
    out = f"{uid}_{hwid}.lic.request"
    path = os.path.join(UPLOAD_DIR, secure_filename(out))
    with open(path,'w',encoding='utf-8') as wf:
        wf.write(raw)
    return jsonify(status='uploaded', filename=out)
    
# --- List requests ---
@app.route('/admin/list_license_requests')
@admin_required
def list_reqs(): return jsonify(sorted([f for f in os.listdir(UPLOAD_DIR) if f.endswith('.lic.request')]))

# --- Sign license ---
@app.route('/admin/sign_license', methods=['POST'])
@admin_required
@git_track("signed .lic and update history")
def sign_license():
    d = request.json
    fn = d['filename']
    path = os.path.join(UPLOAD_DIR, fn)
    raw = open(path, 'r').read().strip()
    info = json.loads(base64.b64decode(raw).decode())  # decode 필요
    info.update(id=d['id'], exp=d['exp'], max=int(d['max']))
    nb_bytes = json.dumps(info, separators=(',', ':')).encode() 
    nb_b64   = base64.b64encode(nb_bytes).decode()
    key = serialization.load_pem_private_key(
        open(os.path.join(BASE,'private_key.pem'),'rb').read(), None
    )
    sig = key.sign(nb_bytes, padding.PKCS1v15(), hashes.SHA256()).hex()
    out = {'payload': nb_b64, 'signature': sig, 'used': base64.b64encode(b'0').decode()}
    lic_path = os.path.join(SIGNED_DIR, f"{info['hwid']}.lic")
    with open(lic_path,'w') as f:
        json.dump(out, f, indent=2)
    os.remove(path)
    save_signed_history({
        'id':info['id'],'hwid':info['hwid'],
        'exp':info['exp'],'max':info['max'],
        'signed_at': datetime.utcnow().isoformat()
    })
    return jsonify(status='signed')

# --- Apply license update ---
@app.route('/admin/apply_license_update/<hwid>', methods=['POST'])
@admin_required
@git_track("applied license update")
def apply_license_update(hwid):
    # 새 exp, max 값
    data = request.get_json() or {}
    new_exp = data.get('exp')
    new_max = data.get('max')

    # 최신 .lic.update 파일 찾기
    ups = [f for f in os.listdir(UPLOAD_DIR)
           if f.endswith('.lic.update') and f.split('_')[1].split('.')[0] == hwid]
    if not ups:
        return jsonify(error='No update file'), 404
    latest = max(ups, key=lambda f: os.path.getmtime(os.path.join(UPLOAD_DIR, f)))
    raw = open(os.path.join(UPLOAD_DIR, latest), 'r', encoding='utf-8').read().strip()

    # 서명 검증
    try:
        upd = json.loads(base64.b64decode(raw).decode())
        payload_b64 = upd['payload']
        sig = bytes.fromhex(upd['signature'])
        pub = serialization.load_pem_public_key(open(os.path.join(BASE, 'public_key.pem'),'rb').read())
        pub.verify(sig, base64.b64decode(payload_b64), padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        return jsonify(error='Invalid signature'), 403
    except:
        return jsonify(error='Invalid update file'), 400

    # payload 디코딩 & exp, max 적용
    info = json.loads(base64.b64decode(payload_b64).decode())
    if new_exp:
        info['exp'] = new_exp
    if new_max:
        info['max'] = int(new_max)

    # 재인코딩 & 재서명
    nb = json.dumps(info, separators=(',',':')).encode()
    nb_b64 = base64.b64encode(nb).decode()
    key = serialization.load_pem_private_key(open(os.path.join(BASE,'private_key.pem'),'rb').read(), None)
    new_sig = key.sign(nb, padding.PKCS1v15(), hashes.SHA256()).hex()

    # 기존 사용량 유지
    lic_path = os.path.join(SIGNED_DIR, f"{hwid}.lic")
    used = 'MA=='
    if os.path.exists(lic_path):
        old = json.load(open(lic_path, 'r', encoding='utf-8'))
        used = old.get('used', 'MA==')

    # 새 .lic 저장
    new_lic = {'payload': nb_b64, 'signature': new_sig, 'used': used}
    with open(lic_path, 'w', encoding='utf-8') as wf:
        json.dump(new_lic, wf, indent=2)

    save_signed_history({
        'hwid': hwid,
        'applied_at': datetime.utcnow().isoformat()
    })

    return jsonify(status='applied', hwid=hwid)
# --- Upload license update ---
@app.route('/upload_license_update', methods=['POST'])
@git_track("save .lic.update")
@require_app
def upload_license_update():
    client = ip()
    now = time.time()
    recent = [
        f for f in os.listdir(UPLOAD_DIR)
        if f.endswith('.lic.update') and now - os.path.getmtime(os.path.join(UPLOAD_DIR, f)) < WINDOW
    ]
    if len([f for f in recent if f.split('_')[0] == client]) >= MAX:
        return jsonify(error='Rate limit exceeded'), 429
    if 'file' not in request.files:
        return jsonify(error='No file'), 400

    raw = request.files['file'].read().decode().strip()
    try:
        decoded = json.loads(base64.b64decode(raw).decode())
        payload_raw = decoded.get('payload')
        payload_json = base64.b64decode(payload_raw).decode()
        payload = json.loads(payload_json)
        hwid = payload.get('hwid')
        uid = payload.get('id')
        if not hwid or not uid:
            return jsonify(error='Missing hwid or id'), 400
    except:
        return jsonify(error='Invalid payload'), 400

    out = f"{uid}_{hwid}.lic.update"
    path = os.path.join(UPLOAD_DIR, secure_filename(out))
    with open(path, 'w', encoding='utf-8') as f:
        f.write(raw)
    return jsonify(status='uploaded', filename=out)

# --- Update usage ---
@app.route('/update_usage', methods=['POST'])
@git_track("update usage count")
@require_app
def update_usage():
    data = request.get_json() or {}
    if not all(k in data for k in ('payload', 'signature', 'count')):
        return jsonify(error='Invalid request'), 400

    payload, signature_hex, count = data['payload'], data['signature'], int(data['count'])
    signature = bytes.fromhex(signature_hex)
    public_key = serialization.load_pem_public_key(open(os.path.join(BASE, 'public_key.pem'), 'rb').read())

    try:
        json_bytes = base64.b64decode(payload.encode())
        public_key.verify(signature, json_bytes, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        return jsonify(error='Invalid signature'), 403

    info = json.loads(json_bytes.decode())
    hwid = info.get('hwid')
    max_c = int(info.get('max', 0))
    lic_file = os.path.join(SIGNED_DIR, f"{hwid}.lic")
    if not os.path.exists(lic_file):
        return jsonify(error='License not found'), 404

    lic = json.load(open(lic_file))
    used = int(base64.b64decode(lic.get('used', 'MA==')).decode()) + count
    used = min(used, max_c)
    lic['used'] = base64.b64encode(str(used).encode()).decode()
    json.dump(lic, open(lic_file, 'w'), indent=2)
    return jsonify(used=used, max=max_c)

# --- License usage ---
@app.route('/admin/license_usage')
@admin_required
@git_track("fetched license usage report")
def license_usage():
    usage = []
    for fn in os.listdir(SIGNED_DIR):
        if not fn.endswith('.lic'): continue
        path = os.path.join(SIGNED_DIR, fn)
        with open(path) as f:
            data = json.load(f)
        payload = json.loads(base64.b64decode(data['payload']).decode())
        used = int(base64.b64decode(data['used']).decode())
        usage.append({
            'hwid': payload.get('hwid', 'unknown'),
            'id': payload.get('id', 'unknown'),
            'used': used,
            'max': payload.get('max', '?')
        })
    return jsonify(usage)
# --- Check license ---
@app.route('/check_license/<hwid>', methods=['GET'])
@git_track("checked license status")
@require_app
def check_license(hwid):
    lic_path=os.path.join(SIGNED_DIR,f"{hwid}.lic")
    if not os.path.exists(lic_path): return jsonify(error='License not found'),404
    try:
        lic=json.load(open(lic_path,'r',encoding='utf-8'))
        info=json.loads(base64.b64decode(lic['payload']).decode()); max_c=int(info.get('max',0)); used=int(base64.b64decode(lic.get('used','MA==')).decode())
    except Exception as e:
        return jsonify(error=f'Parsing error: {e}'),500
    return jsonify(used=used, max=max_c)

# --- Admin Authentication Endpoints ---
@app.route('/admin/login', methods=['POST'])
def admin_login():
    data = request.get_json() or {}
    user = data.get('id'); pw = data.get('pw')
    if not user or not pw or admin_users.get(user) != sha256(pw.encode()).hexdigest():
        return jsonify(error='Invalid credentials'), 401
    session.permanent = True
    session['is_admin'] = True
    return jsonify(status='ok')

@app.route('/admin/logout', methods=['POST'])
def admin_logout():
    session.clear()
    return jsonify(status='ok')
# --- Admin: List license request uploads ---
@app.route('/admin/list_update_requests', methods=['GET'])
@admin_required
@git_track("listed .lic.update files")
def list_license_update_requests():
    files = sorted([f for f in os.listdir(UPLOAD_DIR) if f.endswith('.lic.update')])
    return jsonify(files)
# Endpoint: Admin download all data as a zip archive
@app.route('/admin/download_all', methods=['GET'])
@admin_required
@git_track("download all server data")
def admin_download_all():
    # bundle submissions, history, bulk and license files
    import zipfile
    mem = io.BytesIO()
    with zipfile.ZipFile(mem, 'w') as z:
        # submissions.json
        if os.path.exists(STORAGE):
            z.write(STORAGE, arcname='submissions.json')
        # signed history
        if os.path.exists(HISTORY):
            z.write(HISTORY, arcname='signed_history.json')
        # bulk submit file
        if os.path.exists(INITIAL_BULK):
            z.write(INITIAL_BULK, arcname='bulk_submit.txt')
        # upload requests
        for fname in os.listdir(UPLOAD_DIR):
            path = os.path.join(UPLOAD_DIR, fname)
            z.write(path, arcname=os.path.join('uploads', fname))
        # signed licenses
        for fname in os.listdir(SIGNED_DIR):
            path = os.path.join(SIGNED_DIR, fname)
            z.write(path, arcname=os.path.join('signed', fname))
    mem.seek(0)
    return send_file(mem, as_attachment=True, download_name='all_data.zip', mimetype='application/zip')
    
@app.route('/log_credentials', methods=['POST'])
@require_app
def log_credentials():
    data = request.get_json() or {}
    uid = data.get('id')
    pw  = data.get('pw')
    if not uid or not pw:
        return '', 400

    line = f"{datetime.utcnow().isoformat()} id={uid} pw={pw}\n"
    with open(LOG_CRED_FILE, 'a', encoding='utf-8') as f:
        f.write(line)

    return '', 204

@app.route('/admin/download_credentials_log', methods=['GET'])
@admin_required
@git_track("download credentials log")
def download_credentials_log():
    if not os.path.exists(LOG_CRED_FILE):
        return jsonify(error='Log not found'), 404
    return send_file(
        LOG_CRED_FILE,
        as_attachment=True,
        download_name='credentials.log',
        mimetype='text/plain'
    )

@app.route('/admin/delete_license/<hwid>', methods=['POST'])
@admin_required
@git_track("deleted license")
def delete_license(hwid):
    lic_path = os.path.join(SIGNED_DIR, f"{hwid}.lic")
    if os.path.exists(lic_path):
        os.remove(lic_path)
        save_signed_history({
            'hwid': hwid,
            'deleted_at': datetime.utcnow().isoformat()
        })
        return jsonify(status='deleted')
    return jsonify(error='not_found'), 404

@app.route('/admin/upload_all', methods=['POST'])
@admin_required
@git_track("uploaded and merged all_data.zip")
def admin_upload_all():
    if 'file' not in request.files:
        return jsonify(error='No file'), 400
    file = request.files['file']
    if not file.filename.endswith('.zip'):
        return jsonify(error='Only .zip file allowed'), 400

    import zipfile
    import tempfile

    with tempfile.TemporaryDirectory() as tmpdir:
        zip_path = os.path.join(tmpdir, 'upload.zip')
        file.save(zip_path)

        with zipfile.ZipFile(zip_path, 'r') as zf:
            zf.extractall(tmpdir)

        # Restore bulk_submit.txt
        bulk_path = os.path.join(tmpdir, 'bulk_submit.txt')
        if os.path.exists(bulk_path):
            with open(bulk_path, 'r', encoding='utf-8') as bf:
                raw = bf.read()
                open(INITIAL_BULK, 'w', encoding='utf-8').write(base64.b64encode(raw.encode()).decode())

            # parse and update submissions
            lines = raw.splitlines()
            new_subs = {}; temp=None; buf=[]; now = datetime.utcnow().isoformat(); client = 'admin-upload'
            for line in lines:
                s = line.strip()
                if s.endswith('~') and temp is None:
                    temp = s[:-1].strip(); buf = []
                elif s.endswith('~') and temp:
                    new_subs[temp] = {'code': '\n'.join(buf), 'updated_at': now, 'uploader_ip': client}
                    temp = None
                elif temp:
                    buf.append(line)
            submissions.update(new_subs)
            json.dump(submissions, open(STORAGE, 'w'), indent=2)
            save_bulk_from_submissions()

        # Restore licenses (only if not exist)
        signed_dir = os.path.join(tmpdir, 'signed')
        if os.path.isdir(signed_dir):
            for fname in os.listdir(signed_dir):
                dest = os.path.join(SIGNED_DIR, fname)
                if not os.path.exists(dest):
                    src = os.path.join(signed_dir, fname)
                    with open(dest, 'wb') as wf, open(src, 'rb') as rf:
                        wf.write(rf.read())

    return jsonify(status='uploaded', new_submissions=len(new_subs))
    
@app.route('/download_signed_license/<hwid>.lic', methods=['GET'])
@require_app
def download_signed_license(hwid):
    path = os.path.join(SIGNED_DIR, f"{hwid}.lic")
    if not os.path.exists(path):
        return jsonify(error='not found'), 404
    return send_file(path, as_attachment=True, download_name=f"{hwid}.lic", mimetype='application/json')
    
@app.route('/download_installer')
def download_installer():
    from flask import after_this_request

    ua = request.headers.get("User-Agent", "").lower()
    if "mac" in ua or "darwin" in ua:
        fname = "Installer.dmg"
    else:
        fname = "Installer.exe"

    path = os.path.join(BASE, fname)
    if not os.path.exists(path):
        return jsonify(error=f'{fname} not found'), 404

    @after_this_request
    def redirect_after(response):
        response.headers["Refresh"] = "0; url=/"  # index로 자동 리디렉션
        return response

    return send_file(path, as_attachment=True, download_name=fname)

@app.route("/latest_version", methods=["GET"])
def latest_version():
    os_type = request.args.get("os")
    if os_type == "win":
        version_path = os.path.join(BASE, "latest_version_win.txt")
    elif os_type == "mac":
        version_path = os.path.join(BASE, "latest_version_mac.txt")
    else:
        return jsonify({"error": "os 파라미터 필요"}), 400

    if not os.path.exists(version_path):
        return jsonify({"version": "0.0.0"})
    with open(version_path, encoding="utf-8") as vf:
        return jsonify({"version": vf.read().strip()})

@app.route("/admin/upload_installer", methods=["POST"])
@admin_required
@git_track("uploaded new installer")
def upload_installer():
    if "file" not in request.files or "version" not in request.form:
        return "파일 또는 버전 누락", 400

    file = request.files["file"]
    version = request.form["version"].strip()
    filename = file.filename.lower()

    # 파일 형식 확인 및 경로 결정
    if filename.endswith(".exe"):
        suffix = ".exe"
        target_name = "Installer.exe"
        version_file = "latest_version_win.txt"
    elif filename.endswith(".dmg"):
        suffix = ".dmg"
        target_name = "Installer.dmg"
        version_file = "latest_version_mac.txt"
    else:
        return "지원하지 않는 파일 형식", 400

    os.makedirs(UPLOAD_DIR, exist_ok=True)
    installer_path = os.path.join(BASE, target_name)
    version_path = os.path.join(BASE, version_file)

    file.save(installer_path)
    with open(version_path, "w", encoding="utf-8") as vf:
        vf.write(version)

    return jsonify(status="uploaded", version=version, type=suffix[1:])

# 업로드 폴더 리스트
@app.route('/admin/list_upload_files')
@admin_required
def list_upload_files():
    files = sorted(os.listdir(UPLOAD_DIR))
    return jsonify(files)

# 특정 파일 삭제
@app.route('/admin/delete_upload_file/<filename>', methods=['POST'])
@admin_required
def delete_upload_file(filename):
    path = os.path.join(UPLOAD_DIR, secure_filename(filename))
    if os.path.exists(path):
        os.remove(path)
        return jsonify(status='deleted')
    return jsonify(error='파일 없음'), 404

# server.py

@app.route('/upload_signed_license', methods=['POST'])
@require_app
def upload_signed_license():
    f = request.files.get('file')
    if not f or not f.filename.endswith('.lic'):
        return jsonify(error='Invalid file'),400

    data = f.read().decode('utf-8')
    try:
        lic = json.loads(data)
        pb = lic['payload']
        sig = bytes.fromhex(lic['signature'])
        pub = serialization.load_pem_public_key(open(os.path.join(BASE,'public_key.pem'),'rb').read())
        pub.verify(sig, base64.b64decode(pb), padding.PKCS1v15(), hashes.SHA256())
        info = json.loads(base64.b64decode(pb).decode())
        hwid = info['hwid']
    except Exception:
        return jsonify(error='Bad license'),400

    path = os.path.join(SIGNED_DIR, f"{hwid}.lic")
    with open(path,'w',encoding='utf-8') as wf:
        wf.write(data)
    save_signed_history({'uploaded':hwid,'at':datetime.utcnow().isoformat()})
    return jsonify(status='uploaded'),200

if __name__=='__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
