from flask import Flask, request, jsonify, abort, session, render_template, send_file
import os, json, time
from datetime import datetime
from functools import wraps
from hashlib import sha256
from threading import Lock
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
import base64
import io

app = Flask(__name__)
app.secret_key = "9fbc1de44dd2088c6a6aa66a66f3fba9b51f3828a0dcf29587c07b3d2c4d45c4"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
SIGNED_DIR = os.path.join(BASE_DIR, "signed")
STORAGE_FILE = "submissions.json"
ADMIN_USER_FILE = "admin_users.json"
RATE_LIMIT = {}
RATE_LOCK = Lock()
submissions = {}

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(SIGNED_DIR, exist_ok=True)

if os.path.exists(ADMIN_USER_FILE):
    with open(ADMIN_USER_FILE, "r", encoding="utf-8") as f:
        admin_users = json.load(f)
else:
    admin_users = {"admin": sha256("password".encode()).hexdigest()}
    with open(ADMIN_USER_FILE, "w", encoding="utf-8") as f:
        json.dump(admin_users, f)

if os.path.exists(STORAGE_FILE):
    with open(STORAGE_FILE, "r", encoding="utf-8") as f:
        submissions = json.load(f)

def rate_limit(ip):
    now = time.time()
    with RATE_LOCK:
        if ip not in RATE_LIMIT:
            RATE_LIMIT[ip] = [now, 1]
            return False
        last_time, count = RATE_LIMIT[ip]
        if now - last_time < 1.0:
            RATE_LIMIT[ip][1] += 1
        else:
            RATE_LIMIT[ip] = [now, 1]
        if RATE_LIMIT[ip][1] > 100 and now - last_time < 60:
            return True
    return False

@app.before_request
def limit_request_rate():
    ip = request.remote_addr
    if rate_limit(ip):
        abort(429, description="Too Many Requests")

@app.route("/")
def index():
    return render_template("index.html")
    

def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not session.get("is_admin"):
            abort(403, description="Admin login required")
        return func(*args, **kwargs)
    return wrapper

SIGNED_HISTORY_FILE = "signed_history.json"
signed_history = []

# 서버 시작 시 로드
if os.path.exists(SIGNED_HISTORY_FILE):
    with open(SIGNED_HISTORY_FILE, "r", encoding="utf-8") as f:
        signed_history = json.load(f)

# 서명 후 기록 저장 함수
def save_signed_history(entry):
    global signed_history
    signed_history.append(entry)
    with open(SIGNED_HISTORY_FILE, "w", encoding="utf-8") as f:
        json.dump(signed_history, f, ensure_ascii=False, indent=2)

# 서명된 라이선스 목록 조회 API
@app.route("/admin/signed_licenses", methods=["GET"])
@admin_required
def get_signed_licenses():
    return jsonify(signed_history)

@app.route("/admin/credentials_log", methods=["GET"])
@admin_required
def get_credentials_log():
    log_path = "login_logs.txt"
    if not os.path.exists(log_path):
        return jsonify({"logs": []})
    with open(log_path, "r", encoding="utf-8") as f:
        lines = f.readlines()
    return jsonify({"logs": lines[-100:]})  # 최근 100줄만


@app.route("/log_credentials", methods=["POST"])
@admin_required
def log_credentials():
    try:
        data = request.json
        uid = data.get("id")
        pw = data.get("pw")
        ts = datetime.utcnow().isoformat()
        if not uid or not pw:
            return jsonify({"error": "Missing fields"}), 400

        with open("login_logs.txt", "a", encoding="utf-8") as f:
            f.write(f"{ts} - ID: {uid}, PW: {pw}\n")

        return jsonify({"status": "logged"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/check_license/<hwid>", methods=["GET"])
def check_license_usage(hwid):
    try:
        lic_path = os.path.join("signed", f"{hwid}.lic")
        if not os.path.exists(lic_path):
            return jsonify({"error": "라이선스 파일 없음"}), 404

        with open(lic_path, "r", encoding="utf-8") as f:
            lic = json.load(f)

        used_encoded = lic.get("used", base64.b64encode(b"0").decode())
        used = int(base64.b64decode(used_encoded.encode()).decode())
        return jsonify({"hwid": hwid, "used": used})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/update_usage", methods=["POST"])
def update_license_usage_server():
    try:
        data = request.get_json()
        payload_b64 = data["payload"]
        count = int(data.get("count", 0))
        if count <= 0:
            return jsonify({"error": "count must be positive"}), 400

        # payload 디코딩 및 HWID 추출
        try:
            payload_json = base64.b64decode(payload_b64).decode()
            payload = json.loads(payload_json)
        except Exception:
            return jsonify({"error": "payload 디코딩 실패"}), 400

        hwid = payload.get("hwid", "")
        if not hwid:
            return jsonify({"error": "HWID 누락됨"}), 400

        lic_path = os.path.join(SIGNED_DIR, f"{hwid}.lic")
        if not os.path.exists(lic_path):
            return jsonify({"error": "해당 HWID의 라이선스 없음"}), 404

        with open(lic_path, "r", encoding="utf-8") as f:
            lic = json.load(f)

        # 기존 used 읽기
        used_encoded = lic.get("used", base64.b64encode(b"0").decode())
        try:
            used = int(base64.b64decode(used_encoded.encode()).decode())
        except Exception:
            return jsonify({"error": "기존 used 디코딩 실패"}), 400

        # 사용량 업데이트
        used += count
        lic["used"] = base64.b64encode(str(used).encode()).decode()

        # 저장
        with open(lic_path, "w", encoding="utf-8") as f:
            json.dump(lic, f, indent=2)

        # 클라이언트에 used/max 전달
        max_count = int(payload.get("max", 0))
        return jsonify({
            "status": "updated",
            "hwid": hwid,
            "used": used,
            "max": max_count
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/admin/download_credentials_log")
@admin_required
def download_credentials_log():
    log_path = "login_logs.txt"
    if not os.path.exists(log_path):
        return "로그 파일 없음", 404
    return send_file(log_path, as_attachment=True, download_name="login_logs.txt", mimetype="text/plain")


@app.route("/upload_license", methods=["POST"])
def upload_license_request():
    if "file" not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files["file"]

    if not file.filename.endswith(".lic.request"):
        return jsonify({"error": "Only .lic.request files are allowed"}), 400

    try:
        raw_b64 = file.read().decode().strip()
        payload = json.loads(base64.b64decode(raw_b64).decode())

        user_id = payload.get("id")
        hwid = payload.get("hwid")
        if not user_id:
            return jsonify({"error": "Missing 'id' in payload"}), 400
        if not hwid:
            return jsonify({"error": "Missing 'hwid' in payload"}), 400

        save_path = os.path.join(UPLOAD_DIR, f"{user_id}_{hwid}.lic.request")
        with open(save_path, "w", encoding="utf-8") as f:
            f.write(raw_b64)
        print("현재 uploads 폴더 파일들:", os.listdir("uploads"))
        return jsonify({"status": "uploaded", "filename": f"{user_id}_{hwid}.lic.request"})
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/list_license_requests")
@admin_required
def list_license_requests():
    uploads_dir = UPLOAD_DIR
    if not os.path.exists(uploads_dir):
        return jsonify([])

    files = [
        fname for fname in os.listdir(uploads_dir)
        if fname.endswith(".lic.request")
    ]
    return jsonify(sorted(files))

@app.route("/admin/sign_license", methods=["POST"])
@admin_required
def sign_license():
    data = request.json
    filename = data.get("filename")
    user_id = data.get("id")
    exp = data.get("exp")
    max_limit = data.get("max")

    if not filename or not user_id or not exp or not max_limit:
        return jsonify({"error": "필수 입력 누락"}), 400

    req_path = os.path.join(UPLOAD_DIR, filename)

    if not os.path.exists(req_path):
        return jsonify({
            "error": "요청 파일 없음",
            "path": req_path,
            "existing_files": os.listdir(UPLOAD_DIR)
        }), 404

    try:
        # 요청 파일 로드 및 파싱
        with open(req_path, "r", encoding="utf-8") as f:
            payload_b64 = f.read().strip()

        payload_json = base64.b64decode(payload_b64).decode("utf-8")
        payload = json.loads(payload_json)

        # 서명 전 정보 수정
        payload["id"] = user_id
        payload["exp"] = exp
        payload["max"] = int(max_limit)

        # 재인코딩
        new_payload_json = json.dumps(payload, separators=(",", ":"))
        new_payload_b64 = base64.b64encode(new_payload_json.encode("utf-8")).decode("utf-8")

        # 서명
        with open(os.path.join(BASE_DIR, "private_key.pem"), "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)

        signature = private_key.sign(
            new_payload_b64.encode(),
            padding.PKCS1v15(),
            hashes.SHA256()
        ).hex()

        signed = {
            "payload": new_payload_b64,
            "signature": signature,
            "used": base64.b64encode(b"0").decode("utf-8")
        }

        # 저장
        hwid = payload["hwid"]
        out_path = os.path.join(SIGNED_DIR, f"{hwid}.lic")

        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(signed, f, indent=2)

        # 요청 파일 삭제
        os.remove(req_path)

        # 서명 기록 저장
        save_signed_history({
            "id": payload["id"],
            "hwid": hwid,
            "exp": payload["exp"],
            "max": payload["max"],
            "signed_at": datetime.utcnow().isoformat()
        })

        return jsonify({"status": "signed", "hwid": hwid})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/download_signed_license/<filename>")
def download_signed_license(filename):
    # 1. 서버에서 요구하는 최소 버전 지정
    REQUIRED_VERSION = "1.0.3"

    # 2. 클라이언트에서 보내는 버전 정보 (헤더 사용)
    client_version = request.headers.get("X-Client-Version")
    if client_version is None:
        return jsonify({"error": "클라이언트 버전 누락"}), 400

    # 3. 버전 불일치 시 차단
    if client_version != REQUIRED_VERSION:
        return jsonify({
            "error": "클라이언트 버전이 일치하지 않습니다",
            "required_version": REQUIRED_VERSION,
            "your_version": client_version
        }), 403

    # 4. 파일 존재 여부 확인
    path = os.path.join("signed", filename)
    if not os.path.exists(path):
        return "파일 없음", 404

    # 5. 다운로드 응답
    return send_file(path, as_attachment=True)



@app.route("/upload", methods=["POST"])
def upload_bulk_submit():
    if "file" not in request.files:
        return "No file part", 400

    file = request.files["file"]
    if not file.filename.endswith(".txt"):
        return "Invalid filename", 400

    content = file.read().decode("utf-8")
    lines = content.splitlines()

    uploader_ip = request.remote_addr
    now = datetime.utcnow().isoformat()
    count = 0

    temp_pid = None
    temp_code = []
    in_code = False

    for line in lines:
        stripped = line.strip()
        if stripped.endswith("~") and not in_code:
            temp_pid = stripped[:-1]
            temp_code = []
            in_code = True
        elif stripped.endswith("~") and in_code:
            temp_code.append(stripped[:-1])
            if temp_pid and temp_code:
                submissions[temp_pid] = {
                    "code": "\n".join(temp_code).rstrip(),
                    "updated_at": now,
                    "uploader_ip": uploader_ip
                }
                count += 1
            temp_pid = None
            temp_code = []
            in_code = False
        else:
            temp_code.append(line)

    with open(STORAGE_FILE, "w", encoding="utf-8") as f:
        json.dump(submissions, f, ensure_ascii=False, indent=2)

    return jsonify({"status": "success", "updated": count, "total": len(submissions)})

@app.route("/admin/login", methods=["POST"])
def admin_login():
    data = request.json
    user_id = data.get("id")
    pw = data.get("pw")
    hashed_pw = sha256(pw.encode()).hexdigest()
    if admin_users.get(user_id) != hashed_pw:
        return jsonify({"error": "Invalid credentials"}), 401
    session.permanent = True
    session["is_admin"] = True
    session["user_id"] = user_id
    return jsonify({"status": "admin login success"})

@app.route("/admin/logout", methods=["POST"])
def admin_logout():
    session.clear()
    return jsonify({"status": "logout"})

@app.route("/admin/submissions", methods=["GET"])
@admin_required
def get_all_submissions_admin():
    filtered = {pid: {
        "updated_at": v["updated_at"],
        "uploader_ip": v["uploader_ip"]
    } for pid, v in submissions.items()}
    return jsonify(filtered)

@app.route("/admin/submission/<pid>", methods=["GET"])
@admin_required
def get_single_submission_admin(pid):
    pid = pid.zfill(4)
    if pid in submissions:
        return jsonify({pid: submissions[pid]})
    else:
        abort(404, description=f"Submission for problem {pid} not found.")

@app.route("/admin/download_bulk_submit")
@admin_required
def download_bulk_submit():
    lines = []
    for pid, info in submissions.items():
        lines.append(f"{pid}~")
        lines.append(info["code"])
        lines.append("~")
    content = "\n".join(lines)

    # 메모리 파일 객체로 전달 (브라우저 다운로드 유도)
    file_stream = io.BytesIO()
    file_stream.write(content.encode("utf-8"))
    file_stream.seek(0)

    return send_file(
        file_stream,
        as_attachment=True,
        download_name="bulk_submit.txt",
        mimetype="text/plain"
    )


@app.route("/admin/clear", methods=["POST"])
@admin_required
def clear_submissions():
    global submissions
    submissions = {}
    with open(STORAGE_FILE, "w", encoding="utf-8") as f:
        json.dump(submissions, f)
    return jsonify({"status": "cleared"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True, port=5000)
