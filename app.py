from flask import Flask, request, jsonify, abort, session, render_template, send_file
import os, io, json, time, base64
from datetime import datetime, timedelta
from functools import wraps
from hashlib import sha256
from threading import Lock
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

# --- 앱 설정 ---
app = Flask(__name__, template_folder='templates')
app.secret_key = os.getenv('FLASK_SECRET_KEY') or 'secret'
app.permanent_session_lifetime = timedelta(hours=1)

# --- 경로 ---
BASE = os.path.dirname(__file__)
UPLOAD_DIR = os.path.join(BASE, 'uploads')
SIGNED_DIR = os.path.join(BASE, 'signed')
STORAGE = os.path.join(BASE, 'submissions.json')
ADMIN_FILE = os.path.join(BASE, 'admin_users.json')
HISTORY = os.path.join(BASE, 'signed_history.json')
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(SIGNED_DIR, exist_ok=True)

# --- 상태 ---
BLACK, REQ = {}, {}
LOCK = Lock()
MAX = 100; WINDOW=5; BLOCK=3600

# --- 헬퍼 ---
def ip():
    xff = request.headers.get('X-Forwarded-For','')
    return xff.split(',')[0] if xff else request.remote_addr

def admin_required(f):
    @wraps(f)
    def w(*a,**k):
        if not session.get('is_admin'): abort(403)
        return f(*a,**k)
    return w

def save_signed_history(entry):
    if os.path.exists(HISTORY):
        history = json.load(open(HISTORY))
    else:
        history = []
    history.append(entry)
    json.dump(history, open(HISTORY, 'w'), indent=2)

# --- 로드 ---
if os.path.exists(ADMIN_FILE): admin_users=json.load(open(ADMIN_FILE))
else:
    admin_users={'admin':sha256('password'.encode()).hexdigest()}
    json.dump(admin_users, open(ADMIN_FILE,'w'), indent=2)
submissions=json.load(open(STORAGE)) if os.path.exists(STORAGE) else {}
signed_history=json.load(open(HISTORY)) if os.path.exists(HISTORY) else []

# --- 레이트리밋 ---
@app.before_request
def rate_limit():
    i=ip(); now=time.time()
    with LOCK:
        BLACK.update({k:v for k,v in BLACK.items() if v>now})
        if i in BLACK: abort(403)
        REQ.setdefault(i,[]).append(now)
        REQ[i]=[t for t in REQ[i] if now-t<=WINDOW]
        if len(REQ[i])>MAX:
            BLACK[i]=now+BLOCK; abort(403)

# --- 뷰 ---
@app.route('/')
def index(): return render_template('index.html')
@app.route('/upload.html')
def page_upload(): return render_template('upload.html')
@app.route('/license.html')
def page_license(): return render_template('license.html')
@app.route('/admin.html')
@admin_required
def page_admin(): return render_template('admin.html')

# --- 제출 업로드 ---
@app.route('/upload', methods=['POST'])
def upload_bulk():
    if 'file' not in request.files: return jsonify(error='No file'),400
    f=request.files['file']; fn=secure_filename(f.filename)
    if not fn.endswith('.txt'): return jsonify(error='Only .txt'),400
    content=f.read().decode('utf-8'); lines=content.splitlines()
    now_iso=datetime.utcnow().isoformat(); i=ip()
    new_subs=submissions.copy(); cnt=0; temp=None; buf=[]
    for line in lines:
        s=line.strip()
        if s.endswith('~') and temp is None:
            temp=s[:-1].strip(); buf=[]
        elif s.endswith('~') and temp:
            new_subs[temp]={'code':'\n'.join(buf),'updated_at':now_iso,'uploader_ip':i}
            cnt+=1; temp=None
        elif temp: buf.append(line)
    submissions.clear(); submissions.update(new_subs)
    json.dump(submissions, open(STORAGE,'w'), indent=2)
    return jsonify(status='ok',updated=cnt,total=len(new_subs))

# --- bulk submit download public (base64) ---
@app.route('/download_bulk_submit', methods=['GET'])
def download_public():
    if not os.path.exists(STORAGE):
        return jsonify(error='none'), 404

    with open(STORAGE, 'r', encoding='utf-8') as f:
        data = json.load(f)

    # 문제 번호 순 정렬
    items = sorted(data.items(), key=lambda x: x[0])
    content = ''.join(f"{pid}~{v['code']}~" for pid, v in items)

    # Base64 인코딩 후 JSON으로 반환
    content_b64 = base64.b64encode(content.encode('utf-8')).decode('utf-8')
    return jsonify({
        'filename': 'bulk_submit.txt.b64',
        'content_b64': content_b64
    })


# --- bulk submit download admin (plain text) ---
@app.route('/admin/download_bulk_submit')
@admin_required
def download_admin():
    buf=io.BytesIO(''.join(f"{pid}~{v['code']}~" for pid,v in submissions.items()).encode())
    buf.seek(0)
    return send_file(buf,as_attachment=True,download_name='bulk_submit.txt')

# --- 관리자 로그인 ---
@app.route('/admin/login',methods=['POST'])
def admin_login():
    data=request.json; u,p=data.get('id'),data.get('pw')
    if admin_users.get(u)!=sha256(p.encode()).hexdigest():return jsonify(error='Invalid'),401
    session.permanent=True; session['is_admin']=True
    return jsonify(status='ok')
@app.route('/admin/logout',methods=['POST'])
def admin_logout(): session.clear(); return jsonify(status='ok')

# --- 기타 admin API ---
@app.route('/admin/blacklist')
@admin_required
def view_black(): return jsonify(blacklisted_ips=list(BLACK.keys()))

@app.route('/admin/clear', methods=['POST'])
@admin_required
def clear_subs(): submissions.clear(); json.dump(submissions,open(STORAGE,'w'),indent=2); return jsonify(status='cleared')

# --- 라이선스 요청 업로드 ---
@app.route('/upload_license', methods=['POST'])
def upload_license():
    if 'file' not in request.files:
        return jsonify(error='No file'), 400

    f = request.files['file']
    raw_b64 = f.read().decode('utf-8').strip()

    # payload 디코딩해서 id, hwid 추출
    try:
        payload_json = base64.b64decode(raw_b64.encode('utf-8')).decode('utf-8')
        info = json.loads(payload_json)
        user_id = info.get('id', 'unknown')
        hwid = info.get('hwid', '')
    except Exception:
        return jsonify(error='Invalid payload'), 400

    # rate limit check: user_id 기준
    now = time.time()
    for ex in os.listdir(UPLOAD_DIR):
        if ex.startswith(user_id + '_') and now - os.path.getmtime(os.path.join(UPLOAD_DIR, ex)) < WINDOW:
            return jsonify(error='Retry later'), 429

    # 저장 파일명: {id}_{hwid}.lic.request
    out_name = f"{user_id}_{hwid}.lic.request"
    out_path = os.path.join(UPLOAD_DIR, secure_filename(out_name))
    with open(out_path, 'w', encoding='utf-8') as wf:
        wf.write(raw_b64)

    return jsonify(status='uploaded', filename=out_name)

# --- 서명 & 히스토리 ---
@app.route('/list_license_requests')
@app.route('/admin/list_license_requests')
@admin_required
def list_reqs(): return jsonify(sorted([f for f in os.listdir(UPLOAD_DIR) if f.endswith('.lic.request')]))
@app.route('/admin/sign_license',methods=['POST'])
@admin_required
def sign_license():
    d=request.json; fn=d['filename']; path=os.path.join(UPLOAD_DIR,fn)
    pl=json.loads(base64.b64decode(open(path).read()))
    pl.update(id=d['id'],exp=d['exp'],max=int(d['max']))
    nb=base64.b64encode(json.dumps(pl,separators=(',',':')).encode()).decode()
    key=serialization.load_pem_private_key(open(os.path.join(BASE,'private_key.pem'),'rb').read(),None)
    sig=key.sign(nb.encode(),padding.PKCS1v15(),hashes.SHA256()).hex()
    out={'payload':nb,'signature':sig,'used':base64.b64encode(b'0').decode()}
    open(os.path.join(SIGNED_DIR,f"{pl['hwid']}.lic"),'w').write(json.dumps(out,indent=2))
    os.remove(path)
    save_signed_history({'id':pl['id'],'hwid':pl['hwid'],'exp':pl['exp'],'max':pl['max'],'signed_at':datetime.utcnow().isoformat()})
    return jsonify(status='signed')
@app.route('/admin/signed_licenses')
@admin_required
def signed_list(): return jsonify(json.load(open(HISTORY)) if os.path.exists(HISTORY) else [])

# --- Public endpoint: upload license update (.lic.update) ---
@app.route('/upload_license_update', methods=['POST'])
def upload_license_update():
    # Rate-limit by IP
    client_ip = ip()
    now = time.time()
    recent = [f for f in os.listdir(UPLOAD_DIR)
              if f.endswith('.lic.update') and now - os.path.getmtime(os.path.join(UPLOAD_DIR, f)) < WINDOW]
    # count uploads for this IP (filename prefix is client_ip)
    ip_uploads = [f for f in recent if f.split('_')[0] == client_ip]
    if len(ip_uploads) >= MAX:
        return jsonify(error='Rate limit exceeded'), 429

    if 'file' not in request.files:
        return jsonify(error='No file'), 400
    f = request.files['file']
    raw_b64 = f.read().decode('utf-8').strip()
    # decode payload to get hwid
    try:
        payload_json = base64.b64decode(raw_b64.encode('utf-8')).decode('utf-8')
        info = json.loads(payload_json)
        hwid = info.get('hwid', 'unknown')
    except:
        return jsonify(error='Invalid payload'), 400
    # save update file named <hwid>_<client_ip>.lic.update to allow per-IP
    out_name = f"{hwid}_{client_ip}.lic.update"
    out_path = os.path.join(UPLOAD_DIR, secure_filename(out_name))
    with open(out_path, 'w', encoding='utf-8') as wf:
        wf.write(raw_b64)
    return jsonify(status='uploaded', filename=out_name)

# --- Server: download signed license endpoint ---
@app.route('/download_signed_license/<hwid>.lic', methods=['GET'])
def download_signed_license(hwid):
    # 파일 경로
    signed_path = os.path.join(SIGNED_DIR, f"{hwid}.lic")
    if not os.path.exists(signed_path):
        return jsonify(error='Not found'), 404
    # 인증된 라이선스 파일 전송
    return send_file(signed_path, as_attachment=True, download_name=f"{hwid}.lic")

# --- Admin endpoint: apply license update ---
@app.route('/admin/apply_license_update/<hwid>', methods=['POST'])
@admin_required
def apply_license_update(hwid):
    # find latest update file for hwid
    files = [f for f in os.listdir(UPLOAD_DIR) if f.startswith(f"{hwid}_") and f.endswith('.lic.update')]
    if not files:
        return jsonify(error='No update file'), 404
    latest = max(files, key=lambda f: os.path.getmtime(os.path.join(UPLOAD_DIR, f)))
    raw_b64 = open(os.path.join(UPLOAD_DIR, latest), 'r', encoding='utf-8').read().strip()
    try:
        data = json.loads(base64.b64decode(raw_b64).decode('utf-8'))
        payload = data['payload']
        signature = data['signature']
    except:
        return jsonify(error='Invalid update file'), 400
    # overwrite signed license
    out_path = os.path.join(SIGNED_DIR, f"{hwid}.lic")
    with open(out_path, 'w', encoding='utf-8') as sf:
        json.dump({'payload': payload, 'signature': signature, 'used': base64.b64encode(b'0').decode()}, sf, indent=2)
    save_signed_history({'hwid': hwid, 'applied_at': datetime.utcnow().isoformat()})
    return jsonify(status='applied', hwid=hwid)

if __name__=='__main__': app.run(host='0.0.0.0',port=5000,debug=True)
