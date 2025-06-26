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

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(SIGNED_DIR, exist_ok=True)
LOCK = Lock()
BLACK, REQ = {}, {}
# Fixed-window rate limit parameters
MAX, WINDOW, BLOCK = 100, 5, 3600  # requests, seconds, block duration

# Token Bucket parameters for all endpoints
TOKEN_BUCKET = {}
TB_CAPACITY = 10      # max tokens per IP
TB_FILL_RATE = 1.0    # tokens replenished per second

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

# Data loading
if os.path.exists(ADMIN_FILE): admin_users=json.load(open(ADMIN_FILE))
else:
    admin_users={'admin':sha256('password'.encode()).hexdigest()}
    json.dump(admin_users,open(ADMIN_FILE,'w'),indent=2)
    git_commit_and_push('Init admin_users')
submissions=json.load(open(STORAGE,'r')) if os.path.exists(STORAGE) else {}
signed_history=json.load(open(HISTORY,'r')) if os.path.exists(HISTORY) else []

# Global rate limit for all endpoints
@app.before_request
def global_rate_limit():
    client, now = ip(), time.time()
    # Clean black list
    BLACK.update({ip:exp for ip,exp in BLACK.items() if exp>now})
    if client in BLACK: abort(429)
    # Token bucket check
    bucket=TOKEN_BUCKET.setdefault(client, {'tokens':TB_CAPACITY,'last':now})
    delta=now-bucket['last']
    bucket['tokens']=min(TB_CAPACITY, bucket['tokens']+delta*TB_FILL_RATE)
    bucket['last']=now
    if bucket['tokens']<1:
        BLACK[client]=now+BLOCK; abort(429)
    bucket['tokens']-=1
    # Fixed-window fallback
    REQ.setdefault(client,[]).append(now)
    REQ[client]=[t for t in REQ[client] if now-t<=WINDOW]
    if len(REQ[client])>MAX:
        BLACK[client]=now+BLOCK; abort(429)

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
def upload_bulk():
    if 'file' not in request.files: return jsonify(error='No file'),400
    f = request.files['file']; fn = secure_filename(f.filename)
    if not fn.endswith('.txt'): return jsonify(error='Only .txt'),400
    content = f.read().decode('utf-8')
    # save raw to INITIAL_BULK
    open(INITIAL_BULK,'w',encoding='utf-8').write(base64.b64encode(content.encode()).decode())
    lines = content.splitlines(); now_iso = datetime.utcnow().isoformat(); client=ip()
    new = {}; cnt=0; temp=None; buf=[]
    for line in lines:
        s=line.strip()
        if s.endswith('~') and temp is None:
            temp=s[:-1].strip(); buf=[]
        elif s.endswith('~') and temp:
            new[temp]={'code':'\n'.join(buf),'updated_at':now_iso,'uploader_ip':client}
            cnt+=1; temp=None
        elif temp: buf.append(line)
    submissions.clear(); submissions.update(new)
    json.dump(submissions, open(STORAGE,'w'), indent=2)
    return jsonify(status='ok', updated=cnt, total=len(new))

# --- Bulk download public ---
@app.route('/download_bulk_submit', methods=['GET'])
def download_public():
    if not os.path.exists(STORAGE): return jsonify(error='none'),404
    data = json.load(open(STORAGE,'r',encoding='utf-8'))
    items=sorted(data.items(), key=lambda x:x[0])
    content=''.join(f"{pid}~{v['code']}~" for pid,v in items)
    b64=base64.b64encode(content.encode()).decode()
    payload={'filename':'bulk_submit.txt.b64','content_b64':b64}
    buf=io.BytesIO(json.dumps(payload,ensure_ascii=False).encode()); buf.seek(0)
    return send_file(buf,mimetype='application/json',as_attachment=True,download_name='bulk_submit.json')

# --- Bulk download admin ---
@app.route('/admin/download_bulk_submit')
@admin_required
@git_track("admin downloaded bulk")
def download_admin():
    content=''.join(f"{pid}~{v['code']}~" for pid,v in submissions.items())
    buf=io.BytesIO(content.encode()); buf.seek(0)
    return send_file(buf,as_attachment=True,download_name='bulk_submit.txt')

# --- Admin clear submissions ---
@app.route('/admin/clear', methods=['POST'])
@admin_required
@git_track("cleared submissions")
def clear_subs():
    submissions.clear(); json.dump(submissions, open(STORAGE,'w'), indent=2)
    return jsonify(status='cleared')

# --- License upload ---
@app.route('/upload_license', methods=['POST'])
@git_track("save .lic.request")
def upload_license():
    # 1) DDoS 방어: IP별 rate limiting
    client = ip()
    now_ts = time.time()
    LICENSE_REQ.setdefault(client, []).append(now_ts)
    # 윈도우(초) 내의 타임스탬프만 남김
    LICENSE_REQ[client] = [t for t in LICENSE_REQ[client] if now_ts - t <= LIC_WINDOW]
    if len(LICENSE_REQ[client]) > LIC_MAX:
        # 블랙리스트에 올리고 즉시 차단
        BLACK[client] = now_ts + BLOCK
        return jsonify(error='Too many requests, temporarily blocked'), 429

    # 2) 기존 payload·UID 기반 재요청 제한
    if 'file' not in request.files:
        return jsonify(error='No file'), 400
    raw = request.files['file'].read().decode().strip()
    try:
        info = json.loads(base64.b64decode(raw.encode()).decode())
        uid = info.get('id', 'unknown')
        hwid = info.get('hwid', '')
    except:
        return jsonify(error='Invalid payload'), 400

    # 3) UID 단위 중복 제한 (WINDOW 초)
    for ex in os.listdir(UPLOAD_DIR):
        if ex.startswith(f"{uid}_") and now_ts - os.path.getmtime(os.path.join(UPLOAD_DIR, ex)) < WINDOW:
            return jsonify(error='Retry later'), 429

    # 4) 정상 저장
    out = f"{uid}_{hwid}.lic.request"
    path = os.path.join(UPLOAD_DIR, secure_filename(out))
    with open(path, 'w', encoding='utf-8') as wf:
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
    d=request.json; fn=d['filename']; path=os.path.join(UPLOAD_DIR,fn)
    pl=json.loads(base64.b64decode(open(path).read()))
    pl.update(id=d['id'], exp=d['exp'], max=int(d['max']))
    nb=base64.b64encode(json.dumps(pl,separators=(',',':')).encode()).decode()
    key=serialization.load_pem_private_key(open(os.path.join(BASE,'private_key.pem'),'rb').read(),None)
    sig=key.sign(nb.encode(),padding.PKCS1v15(),hashes.SHA256()).hex()
    out={'payload':nb,'signature':sig,'used':base64.b64encode(b'0').decode()}
    lic_path=os.path.join(SIGNED_DIR,f"{pl['hwid']}.lic")
    open(lic_path,'w').write(json.dumps(out,indent=2))
    os.remove(path)
    save_signed_history({'id':pl['id'],'hwid':pl['hwid'],'exp':pl['exp'],'max':pl['max'],'signed_at':datetime.utcnow().isoformat()})
    return jsonify(status='signed')

# --- Apply license update ---
@app.route('/admin/apply_license_update/<hwid>', methods=['POST'])
@admin_required
@git_track("applied license update")
def apply_license_update(hwid):
    files=[f for f in os.listdir(UPLOAD_DIR) if f.startswith(f"{hwid}_") and f.endswith('.lic.update')]
    if not files: return jsonify(error='No update file'),404
    latest=max(files, key=lambda f: os.path.getmtime(os.path.join(UPLOAD_DIR,f)))
    raw=open(os.path.join(UPLOAD_DIR,latest)).read().strip()
    try:
        data=json.loads(base64.b64decode(raw).decode()); payload=data['payload']; sig=data['signature']
    except:
        return jsonify(error='Invalid update file'),400
    out_path=os.path.join(SIGNED_DIR,f"{hwid}.lic")
    with open(out_path,'w') as sf:
        json.dump({'payload':payload,'signature':sig,'used':base64.b64encode(b'0').decode()}, sf, indent=2)
    save_signed_history({'hwid':hwid,'applied_at':datetime.utcnow().isoformat()})
    return jsonify(status='applied',hwid=hwid)

# --- Upload license update ---
@app.route('/upload_license_update', methods=['POST'])
@git_track("save .lic.update")
def upload_license_update():
    client=ip(); now=time.time()
    recent=[f for f in os.listdir(UPLOAD_DIR) if f.endswith('.lic.update') and now-os.path.getmtime(os.path.join(UPLOAD_DIR,f))<WINDOW]
    if len([f for f in recent if f.split('_')[0]==client])>=MAX:
        return jsonify(error='Rate limit exceeded'),429
    if 'file' not in request.files: return jsonify(error='No file'),400
    raw=request.files['file'].read().decode().strip()
    try: hwid=json.loads(base64.b64decode(raw).decode()).get('hwid','unknown')
    except: return jsonify(error='Invalid payload'),400
    out=f"{hwid}_{client}.lic.update"; path=os.path.join(UPLOAD_DIR,secure_filename(out))
    open(path,'w',encoding='utf-8').write(raw)
    return jsonify(status='uploaded', filename=out)

# --- Update usage ---
@app.route('/update_usage', methods=['POST'])
@git_track("update usage count")
def update_usage():
    data=request.get_json() or {}
    if not all(k in data for k in ('payload','signature','count')):
        return jsonify(error='Invalid request'),400
    payload, signature_hex, count = data['payload'], data['signature'], int(data['count'])
    signature=bytes.fromhex(signature_hex)
    public_key=serialization.load_pem_public_key(open(os.path.join(BASE,'public_key.pem'),'rb').read())
    try:
        public_key.verify(signature, payload.encode(), padding.PKCS1v15(),hashes.SHA256())
    except InvalidSignature:
        return jsonify(error='Invalid signature'),403
    info=json.loads(base64.b64decode(payload).decode()); hwid=info.get('hwid'); max_c=int(info.get('max',0))
    lic_file=os.path.join(SIGNED_DIR,f"{hwid}.lic")
    if not os.path.exists(lic_file): return jsonify(error='License not found'),404
    lic=json.load(open(lic_file)); used=int(base64.b64decode(lic.get('used','MA==')).decode())+count
    used=min(used, max_c)
    lic['used']=base64.b64encode(str(used).encode()).decode()
    json.dump(lic, open(lic_file,'w'), indent=2)
    return jsonify(used=used, max=max_c)

# --- License usage ---
@app.route('/admin/license_usage')
@admin_required
@git_track("fetched license usage report")
def license_usage():
    out=[]
    for fn in os.listdir(SIGNED_DIR):
        if fn.endswith('.lic'):
            lic=json.load(open(os.path.join(SIGNED_DIR,fn)))
            info=json.loads(base64.b64decode(lic['payload']).decode()); used=int(base64.b64decode(lic.get('used','MA==')).decode());
            out.append({'hwid':info.get('hwid'),'used':used,'max':int(info.get('max',0))})
    return jsonify(out)

# --- Check license ---
@app.route('/check_license/<hwid>', methods=['GET'])
@git_track("checked license status")
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
@app.route('/admin/list_license_requests', methods=['GET'])
@admin_required
@git_track("listed .lic.request files")
def list_license_requests():
    files = sorted([f for f in os.listdir(UPLOAD_DIR) if f.endswith('.lic.request')])
    return jsonify(files)

if __name__=='__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
