from flask import Flask, request, jsonify, abort, session, render_template, send_file
import os
import json
import time
import re
import requests  # ReCaptcha verification
from datetime import datetime
from functools import wraps
from hashlib import sha256
from threading import Lock
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from werkzeug.utils import secure_filename
import base64
import io

# --- Flask 앱 및 설정 ---
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "9fbc1de44dd2088c6a6aa66a66f3fba9b51f3828a0dcf29587c07b3d2c4d45c4")
app.permanent_session_lifetime = timedelta(hours=1)
# --- ReCaptcha 설정 ---
RECAPTCHA_SITE_KEY = os.getenv("RECAPTCHA_SITE_KEY", "6LcMAWwrAAAAAKIAOCMtFhdhfFnqIDQGdxZnb7ay")  # 프론트엔드에 삽입
RECAPTCHA_SECRET_KEY = os.getenv("RECAPTCHA_SECRET_KEY", "6LcMAWwrAAAAACSvC_K-Pdf726e0h3GS5eztKfY5")
RECAPTCHA_VERIFY_URL = "https://www.google.com/recaptcha/api/siteverify"

# --- 디렉토리 및 파일 경로 ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
SIGNED_DIR = os.path.join(BASE_DIR, "signed")
STORAGE_FILE = os.path.join(BASE_DIR, "submissions.json")
ADMIN_USER_FILE = os.path.join(BASE_DIR, "admin_users.json")
SIGNED_HISTORY_FILE = os.path.join(BASE_DIR, "signed_history.json")

# 폴더 생성
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(SIGNED_DIR, exist_ok=True)

# --- 글로벌 상태 및 락 ---
# 블랙리스트는 IP별 만료시간을 저장 (ip: expiry_timestamp)
BLACKLIST = {}
BLACKLIST_LOCK = Lock()
IP_REQUEST_HISTORY = {}
RATE_LOCK = Lock()
MAX_REQUESTS_PER_5MIN = 100
RATE_WINDOW_SECONDS = 300      # 5분
# 블랙리스트 자동 해제 대기 시간 (초)
BLOCK_DURATION = 3600         # 1시간

# --- 헬퍼 함수 ---

def get_client_ip() -> str:
    """
    클라이언트 IP를 결정합니다.
    - X-Client-IP 헤더가 있을 경우(개인 컴퓨터 IP 전송 시) 우선 사용
    - Cloudflare 환경에서는 CF-Connecting-IP 사용
    - X-Forwarded-For 헤더에서 첫 번째 IP 사용
    - 없으면 request.remote_addr (서버에 보이는 공인 IP) 사용
    """
    # 클라이언트가 전송한 개인 LAN IP가 있는 경우
    custom_ip = request.headers.get('X-Client-IP')
    if custom_ip:
        return custom_ip

    # Cloudflare 프록시 환경
    cf_ip = request.headers.get('CF-Connecting-IP')
    if cf_ip:
        return cf_ip

    # 일반 X-Forwarded-For
    xff = request.headers.get('X-Forwarded-For', '')
    if xff:
        return xff.split(',')[0].strip()

    # 기본 client IP (공인 IP)
    return request.remote_addr


def is_valid_hwid(hwid: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-f]{64}", hwid))

# 관리자 인증
def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not session.get("is_admin"):
            abort(403, description="Admin login required")
        return func(*args, **kwargs)
    return wrapper

# 서명 기록 저장
def save_signed_history(entry: dict):
    signed_history.append(entry)
    with open(SIGNED_HISTORY_FILE, "w", encoding="utf-8") as f:
        json.dump(signed_history, f, ensure_ascii=False, indent=2)

# --- 초기 데이터 로드 ---
if os.path.exists(ADMIN_USER_FILE):
    with open(ADMIN_USER_FILE, "r", encoding="utf-8") as f:
        admin_users = json.load(f)
else:
    admin_users = {"admin": sha256("password".encode()).hexdigest()}
    with open(ADMIN_USER_FILE, "w", encoding="utf-8") as f:
        json.dump(admin_users, f)

submissions = {}
if os.path.exists(STORAGE_FILE):
    with open(STORAGE_FILE, "r", encoding="utf-8") as f:
        submissions = json.load(f)

signed_history = []
if os.path.exists(SIGNED_HISTORY_FILE):
    with open(SIGNED_HISTORY_FILE, "r", encoding="utf-8") as f:
        signed_history = json.load(f)

# --- 전역 요청 제한 & 블랙리스트 ---
@app.before_request
def rate_limit_and_blacklist():
    ip = get_client_ip()
    now = time.time()
    # 블랙리스트 만료 해제
    with BLACKLIST_LOCK:
        for blocked_ip, expiry in list(BLACKLIST.items()):
            if now > expiry:
                del BLACKLIST[blocked_ip]
        if ip in BLACKLIST:
            abort(403, "This IP has been temporarily blacklisted.")
    # 레이트 리밋 기록
    IP_REQUEST_HISTORY.setdefault(ip, []).append(now)
    IP_REQUEST_HISTORY[ip] = [
        t for t in IP_REQUEST_HISTORY[ip] if now - t <= RATE_WINDOW_SECONDS
    ]
    if len(IP_REQUEST_HISTORY[ip]) > MAX_REQUESTS_PER_5MIN:
        with BLACKLIST_LOCK:
            BLACKLIST[ip] = now + BLOCK_DURATION
        abort(403, "Too many requests; IP blacklisted.")


# recaptcha required 데코레이터
# reCAPTCHA 검증 데코레이터 (오직 /upload_license 에만 사용)
def require_recaptcha(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # 이미 세션에 한번 검증된 기록이 있으면 재검증 생략
        if session.get('recaptcha_verified'):
            return f(*args, **kwargs)

        # 최초에는 토큰 검사
        token = (
            request.values.get('g-recaptcha-response')
            or request.values.get('recaptcha_token')
            or request.headers.get('X-Recaptcha-Token')
        )
        if not token:
            return jsonify({'error': 'Missing reCAPTCHA token'}), 400

        resp = requests.post(RECAPTCHA_VERIFY_URL, data={
            'secret': RECAPTCHA_SECRET_KEY,
            'response': token
        }, timeout=5)
        if resp.status_code != 200 or not resp.json().get('success'):
            return jsonify({'error': 'reCAPTCHA verification failed', 'details': resp.json()}), 403

        # 검증 성공 시 세션에 기록 (permanent 하려면 여기서 session.permanent=True)
        session.permanent = True
        session['recaptcha_verified'] = True
        return f(*args, **kwargs)
    return decorated



# --- 라우트 정의 ---
@app.route("/blacklist_status")
def blacklist_status():
    """현재 클라이언트 IP의 차단 상태 확인"""
    ip = get_client_ip()
    now = time.time()
    exp = BLACKLIST.get(ip)
    if exp and exp > now:
        return jsonify({"blacklisted": True, "until": exp}), 200
    return jsonify({"blacklisted": False}), 200

@app.route("/unblock_me", methods=["POST"])
def unblock_me():
    """자신의 IP가 차단되어 있을 경우 해제"""
    ip = get_client_ip()
    with BLACKLIST_LOCK:
        if ip in BLACKLIST:
            del BLACKLIST[ip]
            return jsonify({"status": "unblocked", "ip": ip}), 200
    return jsonify({"status": "not_blacklisted", "ip": ip}), 200

@app.route("/admin/unblock/<ip>")
def unblock_ip(ip):
    """관리자 전용: 블랙리스트에서 특정 IP를 즉시 해제"""
    with BLACKLIST_LOCK:
        if ip in BLACKLIST:
            del BLACKLIST[ip]
            return jsonify({"status": "unblocked", "ip": ip})
        else:
            return jsonify({"error": "IP not in blacklist", "ip": ip}), 404

# --- 라우트 정의 ---
@app.route("/")
def index():
    # index.html 템플릿에 site_key 전달
    return render_template("index.html", site_key=RECAPTCHA_SITE_KEY)

@app.route('/upload_license', methods=['POST'])
@require_recaptcha
def upload_license_request():
    # 1) 업로드 디렉토리 준비
    os.makedirs(UPLOAD_DIR, exist_ok=True)

    # 2) 파일 유무/이름 검사
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    filename = secure_filename(file.filename)
    if not filename.endswith('.lic.request'):
        return jsonify({'error': 'Invalid file type'}), 400

    # 3) Base64 문자열 읽기
    raw_b64 = file.read().decode('utf-8', 'ignore').strip()
    try:
        decoded = base64.b64decode(raw_b64)
    except binascii.Error:
        return jsonify({'error': 'Invalid Base64 payload'}), 400

    # 4) JSON 파싱
    try:
        payload = json.loads(decoded)
    except (ValueError, json.JSONDecodeError):
        return jsonify({'error': 'Invalid JSON inside payload'}), 400

    # 5) 필수 필드 확인 & 타입 검사
    required = {'id', 'hwid', 'exp', 'max'}
    missing = required - payload.keys()
    if missing:
        return jsonify({'error': f'Missing fields: {missing}'}), 400

    uid = str(payload['id'])
    hwid = str(payload['hwid'])
    try:
        exp = int(payload['exp'])
        max_limit = int(payload['max'])
    except (TypeError, ValueError):
        return jsonify({'error': 'Fields "exp" and "max" must be integers'}), 400

    # 6) 중복 제한 (WINDOW_SECONDS 내 재업로드 차단)
    now = time.time()
    prefix = f"{uid}_{hwid}"
    for fn in os.listdir(UPLOAD_DIR):
        if fn.startswith(prefix):
            mtime = os.path.getmtime(os.path.join(UPLOAD_DIR, fn))
            if now - mtime < WINDOW_SECONDS:
                retry = int(WINDOW_SECONDS - (now - mtime))
                return jsonify({
                    'error': 'Please wait before retry',
                    'retry_after': retry
                }), 429

    # 7) 파일 저장 (타임스탬프 포함)
    saved_name = f"{prefix}_{int(now)}.lic.request"
    path = os.path.join(UPLOAD_DIR, saved_name)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(raw_b64)

    return jsonify({'status': 'uploaded', 'filename': saved_name}), 201

# --- 추가 라우트 정의 시작 ---

@app.route('/admin/blacklist', methods=['GET'])
@admin_required
def view_blacklist():
    with BLACKLIST_LOCK:
        ips = list(BLACKLIST.keys())
    return jsonify({'blacklisted_ips': ips})


@app.route("/list_license_requests")
@admin_required
def list_license_requests():
    files = [f for f in os.listdir(UPLOAD_DIR) if f.endswith(".lic.request")]
    return jsonify(sorted(files))

@app.route("/admin/sign_license", methods=["POST"])
@admin_required
def sign_license():
    data = request.json
    filename = data.get("filename")
    user_id = data.get("id")
    exp = data.get("exp")
    max_limit = data.get("max")
    if not all([filename, user_id, exp, max_limit]):
        return jsonify({"error": "필수 입력 누락"}), 400
    req_path = os.path.join(UPLOAD_DIR, filename)
    if not os.path.exists(req_path):
        return jsonify({"error": "요청 파일 없음", "existing": os.listdir(UPLOAD_DIR)}), 404
    try:
        raw_b64 = open(req_path, "r", encoding="utf-8").read().strip()
        payload = json.loads(base64.b64decode(raw_b64))
        payload.update({"id": user_id, "exp": exp, "max": int(max_limit)})
        new_b64 = base64.b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode()
        private_key = serialization.load_pem_private_key(
            open(os.path.join(BASE_DIR, "private_key.pem"), "rb").read(), password=None)
        signature = private_key.sign(new_b64.encode(), padding.PKCS1v15(), hashes.SHA256()).hex()
        signed = {"payload": new_b64, "signature": signature, "used": base64.b64encode(b"0").decode()}
        out_path = os.path.join(SIGNED_DIR, f"{payload['hwid']}.lic")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(signed, f, indent=2)
        os.remove(req_path)
        save_signed_history({
            "id": user_id,
            "hwid": payload['hwid'],
            "exp": exp,
            "max": max_limit,
            "signed_at": datetime.utcnow().isoformat()
        })
        return jsonify({"status": "signed", "hwid": payload['hwid']})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/admin/signed_licenses")
@admin_required
def get_signed_licenses():
    return jsonify(signed_history)

@app.route("/admin/credentials_log")
@admin_required
def get_credentials_log():
    log_path = os.path.join(BASE_DIR, "login_logs.txt")
    if not os.path.exists(log_path):
        return jsonify({"logs": []})
    lines = open(log_path, "r", encoding="utf-8").read().splitlines()
    return jsonify({"logs": lines[-100:]})

@app.route("/log_credentials", methods=["POST"])
@admin_required
def log_credentials():
    data = request.json
    uid, pw = data.get("id"), data.get("pw")
    if not uid or not pw:
        return jsonify({"error": "Missing fields"}), 400
    ts = datetime.utcnow().isoformat()
    with open(os.path.join(BASE_DIR, "login_logs.txt"), "a", encoding="utf-8") as f:
        f.write(f"{ts} - ID: {uid}, PW: {pw}")
    return jsonify({"status": "logged"})

@app.route("/check_license/<hwid>")
def check_license_usage(hwid):
    lic_path = os.path.join(SIGNED_DIR, f"{hwid}.lic")
    if not os.path.exists(lic_path):
        return jsonify({"error": "라이선스 파일 없음"}), 404
    lic = json.load(open(lic_path, "r", encoding="utf-8"))
    used = int(base64.b64decode(lic.get("used")).decode())
    return jsonify({"hwid": hwid, "used": used})

@app.route("/update_usage", methods=["POST"])
def update_license_usage_server():
    data = request.get_json()
    payload_b64, count = data.get("payload"), int(data.get("count", 0))
    if count <= 0:
        return jsonify({"error": "count must be positive"}), 400
    payload = json.loads(base64.b64decode(payload_b64))
    hwid = payload.get("hwid")
    lic_path = os.path.join(SIGNED_DIR, f"{hwid}.lic")
    if not os.path.exists(lic_path):
        return jsonify({"error": "해당 HWID의 라이선스 없음"}), 404
    lic = json.load(open(lic_path, "r", encoding="utf-8"))
    used = int(base64.b64decode(lic.get("used")).decode())
    used += count
    lic["used"] = base64.b64encode(str(used).encode()).decode()
    with open(lic_path, "w", encoding="utf-8") as f:
        json.dump(lic, f, indent=2)
    return jsonify({"status": "updated", "hwid": hwid, "used": used, "max": int(payload.get("max", 0))})

@app.route("/admin/download_credentials_log")
@admin_required
def download_credentials_log():
    path = os.path.join(BASE_DIR, "login_logs.txt")
    if not os.path.exists(path):
        abort(404, description="로그 파일 없음")
    return send_file(path, as_attachment=True, download_name="credentials_log.txt")

@app.route("/upload", methods=["POST"])
@require_recaptcha
def upload_bulk_submit():
    import os, json
    from datetime import datetime
    from flask import request, jsonify
    from werkzeug.utils import secure_filename

    global submissions

    # 1) 스토리지 디렉토리 준비
    storage_dir = os.path.dirname(STORAGE_FILE)
    os.makedirs(storage_dir, exist_ok=True)

    # 2) 파일 파트 확인
    if 'file' not in request.files:
        return jsonify({'error': 'No file part in request'}), 400

    file = request.files['file']
    filename = secure_filename(file.filename or '')
    if not filename.lower().endswith('.txt'):
        return jsonify({'error': 'Invalid file type; only .txt allowed'}), 400

    # 3) 내용 읽고 UTF-8 디코딩
    try:
        content = file.read().decode('utf-8')
    except UnicodeDecodeError:
        return jsonify({'error': 'File must be UTF-8 encoded'}), 400

    lines = content.splitlines()
    uploader_ip = get_client_ip()
    now_iso = datetime.utcnow().isoformat()

    # 4) 기존 submissions 불러오기
    try:
        if os.path.exists(STORAGE_FILE):
            with open(STORAGE_FILE, 'r', encoding='utf-8') as f:
                new_subs = json.load(f)
        else:
            new_subs = {}
    except Exception:
        new_subs = {}

    # 5) 파싱 루프 (PID~ code ~ 형태)
    count = 0
    temp_pid = None
    temp_code = []
    in_code = False

    for line in lines:
        stripped = line.strip()
        # 블록 시작 (PID~)
        if stripped.endswith('~') and not in_code:
            pid = stripped[:-1].strip()
            if pid:
                temp_pid = pid
                in_code = True
                temp_code = []
        # 블록 종료 (~)
        elif stripped.endswith('~') and in_code:
            code_text = '\n'.join(temp_code).rstrip()
            new_subs[temp_pid] = {
                'code': code_text,
                'updated_at': now_iso,
                'uploader_ip': uploader_ip
            }
            count += 1
            temp_pid = None
            in_code = False
        # 코드 라인
        elif in_code:
            temp_code.append(line)

    # 6) 디스크에 저장
    try:
        with open(STORAGE_FILE, 'w', encoding='utf-8') as f:
            json.dump(new_subs, f, ensure_ascii=False, indent=2)
    except Exception:
        return jsonify({'error': 'Failed to write storage file'}), 500

    # 7) 메모리 submissions 동기화
    submissions.clear()
    submissions.update(new_subs)

    # 8) 응답
    return jsonify({
        'status': 'success',
        'updated': count,
        'total': len(new_subs)
    }), 200


@app.route("/admin/login", methods=["POST"])
def admin_login():
    data = request.json
    user_id, pw = data.get("id"), data.get("pw")
    if admin_users.get(user_id) != sha256(pw.encode()).hexdigest():
        return jsonify({"error": "Invalid credentials"}), 401
    session.permanent = True
    session.update({"is_admin": True, "user_id": user_id})
    return jsonify({"status": "admin login success"})

@app.route("/admin/logout", methods=["POST"])
def admin_logout():
    session.clear()
    return jsonify({"status": "logout"})

@app.route("/admin/submissions")
@admin_required
def get_all_submissions_admin():
    return jsonify({pid: {"updated_at": v["updated_at"], "uploader_ip": v["uploader_ip"]} for pid, v in submissions.items()})

@app.route("/admin/submission/<pid>")
@admin_required
def get_single_submission_admin(pid):
    pid = pid.zfill(4)
    if pid not in submissions:
        abort(404, description=f"Submission for problem {pid} not found.")
    return jsonify({pid: submissions[pid]})

@app.route("/admin/download_bulk_submit")
@admin_required
def download_bulk_submit():
    content = "".join([f"{pid}~{info['code']}~" for pid, info in submissions.items()])
    buf = io.BytesIO(content.encode())
    buf.seek(0)
    return send_file(buf, as_attachment=True, download_name="bulk_submit.txt", mimetype="text/plain")

@app.route("/admin/clear", methods=["POST"])
@admin_required
def clear_submissions():
    submissions.clear()
    with open(STORAGE_FILE, "w", encoding="utf-8") as f:
        json.dump(submissions, f)
    return jsonify({"status": "cleared"})



# --- 추가 라우트 정의 끝 ---

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
