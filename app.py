from flask import Flask, request, jsonify, abort, session, render_template, send_file
import os, json, time
from datetime import datetime
from functools import wraps
from hashlib import sha256
from threading import Lock
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
import base64

app = Flask(__name__)
app.secret_key = "9fbc1de44dd2088c6a6aa66a66f3fba9b51f3828a0dcf29587c07b3d2c4d45c4"

STORAGE_FILE = "submissions.json"
ADMIN_USER_FILE = "admin_users.json"
RATE_LIMIT = {}
RATE_LOCK = Lock()
submissions = {}

os.makedirs("uploads", exist_ok=True)
os.makedirs("signed", exist_ok=True)

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
        if not user_id:
            return jsonify({"error": "Missing 'id' in payload"}), 400

        save_path = os.path.join("uploads", f"{user_id}.lic.request")
        with open(save_path, "w", encoding="utf-8") as f:
            f.write(raw_b64)

        return jsonify({"status": "uploaded", "filename": f"{user_id}.lic.request"})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/list_license_requests")
@admin_required
def list_license_requests():
    uploads_dir = "uploads"
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
        return "필수 입력 누락", 400

    req_path = os.path.join("uploads", filename)
    if not os.path.exists(req_path):
        return "요청 파일 없음", 404

    try:
        # 요청 파일 로드 및 파싱
        with open(req_path, "r", encoding="utf-8") as f:
            payload_b64 = f.read().strip()
        payload = json.loads(base64.b64decode(payload_b64).decode())

        # 서명 전 정보 덮어쓰기
        payload["id"] = user_id
        payload["exp"] = exp
        payload["max"] = int(max_limit)

        # 재인코딩
        new_payload_b64 = base64.b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode()

        # 서명 수행
        with open("private_key.pem", "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)

        signature = private_key.sign(
            new_payload_b64.encode(),
            padding.PKCS1v15(),
            hashes.SHA256()
        ).hex()

        signed = {
            "payload": new_payload_b64,
            "signature": signature,
            "used": base64.b64encode(b"0").decode()
        }

        # 최종 저장 경로: signed/{user_id}/{hwid}.lic
        save_dir = os.path.join("signed", f"{payload['hwid']}.lic")
        os.makedirs(save_dir, exist_ok=True)
        out_path = save_dir

        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(signed, f, indent=2)

        # 원래 요청 파일은 삭제
        os.remove(req_path)

        return jsonify({"status": "signed", "hwid": payload["hwid"]})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/download_signed_license/<filename>")
def download_signed_license(filename):
    path = os.path.join("signed", filename)
    if not os.path.exists(path):
        return "파일 없음", 404
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
