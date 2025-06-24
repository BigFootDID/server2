```python
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
import base64
import io

# --- Flask 앱 및 설정 ---
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "9fbc1de44dd2088c6a6aa66a66f3fba9b51f3828a0dcf29587c07b3d2c4d45c4")

# --- ReCaptcha 설정 ---
RECAPTCHA_SITE_KEY = os.getenv("RECAPTCHA_SITE_KEY", "6Lcl32srAAAAAHDN2BYp9vyXAFBdFsg4LDu7Gy1w")  # 프론트엔드에 삽입
RECAPTCHA_SECRET_KEY = os.getenv("RECAPTCHA_SECRET_KEY", "6Lcl32srAAAAAIc7uVBu8Bojb2bS2y4w8-_j6ZlR")
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
BLACKLIST = set()
BLACKLIST_LOCK = Lock()
IP_REQUEST_HISTORY = {}
RATE_LOCK = Lock()
MAX_REQUESTS_PER_5MIN = 100
RATE_WINDOW_SECONDS = 300      # 5분

# --- 헬퍼 함수 ---

def get_client_ip() -> str:
    cf_ip = request.headers.get('CF-Connecting-IP')
    if cf_ip:
        return cf_ip
    xff = request.headers.get('X-Forwarded-For', '')
    if xff:
        return xff.split(',')[0].strip()
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
    with BLACKLIST_LOCK:
        if ip in BLACKLIST:
            abort(403, description="Blacklisted IP")
    with RATE_LOCK:
        IP_REQUEST_HISTORY.setdefault(ip, []).append(now)
        IP_REQUEST_HISTORY[ip] = [ts for ts in IP_REQUEST_HISTORY[ip] if now - ts <= RATE_WINDOW_SECONDS]
        if len(IP_REQUEST_HISTORY[ip]) > MAX_REQUESTS_PER_5MIN:
            BLACKLIST.add(ip)
            abort(403, description="Blacklisted due to rate limit")

# --- 라우트 정의 ---
@app.route("/")
def index():
    # index.html 템플릿에 site_key 전달
    return render_template("index.html", site_key=RECAPTCHA_SITE_KEY)

@app.route("/upload_license", methods=["POST"])
def upload_license_request():
    ip = get_client_ip()
    token = request.form.get('g-recaptcha-response') or (request.json and request.json.get('recaptcha_token'))
    if not token:
        return jsonify({"error": "ReCaptcha token is missing"}), 400
    verify = requests.post(
        RECAPTCHA_VERIFY_URL,
        data={"secret": RECAPTCHA_SECRET_KEY, "response": token, "remoteip": ip}
    ).json()
    if not verify.get('success'):
        return jsonify({"error": "ReCaptcha verification failed", "details": verify}), 400

    if "file" not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files["file"]
    if not file.filename.endswith(".lic.request"):
        return jsonify({"error": "Only .lic.request files allowed"}), 400

    try:
        raw_b64 = file.read().decode().strip()
        payload = json.loads(base64.b64decode(raw_b64))
        required_keys = {"id", "hwid", "exp", "max", "timestamp"}
        if not required_keys.issubset(payload.keys()):
            missing = required_keys - payload.keys()
            return jsonify({"error": f"Missing fields: {missing}"}), 400
        user_id, hwid = payload['id'], payload['hwid']
        now_ts = time.time()
        if not user_id.isalnum() or not is_valid_hwid(hwid):
            return jsonify({"error": "Invalid id or HWID format"}), 400
        existing = [f for f in os.listdir(UPLOAD_DIR) if hwid in f]
        for fname in existing:
            if now_ts - os.path.getmtime(os.path.join(UPLOAD_DIR, fname)) < RATE_WINDOW_SECONDS:
                wait = int(RATE_WINDOW_SECONDS - (now_ts - os.path.getmtime(os.path.join(UPLOAD_DIR, fname))))
                return jsonify({"error": "Too soon for same HWID", "wait_seconds": wait}), 429
        save_path = os.path.join(UPLOAD_DIR, f"{user_id}_{hwid}.lic.request")
        with open(save_path, "w", encoding="utf-8") as f:
            f.write(raw_b64)
        return jsonify({"status": "uploaded", "filename": os.path.basename(save_path)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ... 이하 기존 라우트 유지 ...

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
```
