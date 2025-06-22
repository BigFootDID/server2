from flask import Flask, request, jsonify, abort, session, render_template
import os, json, time
from datetime import datetime
from functools import wraps
from hashlib import sha256
from threading import Lock

app = Flask(__name__)
app.secret_key = "your-secret-key-here"

STORAGE_FILE = "submissions.json"
ADMIN_USER_FILE = "admin_users.json"
RATE_LIMIT = {}   # ip → [last_time, count]
RATE_LOCK = Lock()
submissions = {}

# 로드: 관리자 계정
if os.path.exists(ADMIN_USER_FILE):
    with open(ADMIN_USER_FILE, "r", encoding="utf-8") as f:
        admin_users = json.load(f)
else:
    admin_users = {"admin": sha256("password".encode()).hexdigest()}
    with open(ADMIN_USER_FILE, "w", encoding="utf-8") as f:
        json.dump(admin_users, f)

# 로드: 제출 코드
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


@app.route("/upload", methods=["POST"])
def upload_bulk_submit():
    if "file" not in request.files:
        return "No file part", 400

    file = request.files["file"]
    if not file.filename.endswith(".txt"):
        return "Invalid filename", 400

    content = file.read().decode("utf-8")
    lines = content.splitlines()

    if not lines or len(lines) < 2:
        return "Empty or invalid file", 400

    uploader_ip = request.remote_addr
    now = datetime.utcnow().isoformat()
    count = 0

    temp_pid, temp_code = None, []
    for line in lines:
        if line.endswith("~"):
            if temp_pid is None:
                temp_pid = line[:-1].strip()
            else:
                # Save previous block
                code = "\n".join(temp_code).strip()
                if temp_pid and code:
                    submissions[temp_pid] = {
                        "code": code,
                        "updated_at": now,
                        "uploader_ip": uploader_ip
                    }
                    count += 1
                temp_pid = line[:-1].strip()
                temp_code = []
        else:
            temp_code.append(line)

    # 마지막 블록 저장
    if temp_pid and temp_code:
        code = "\n".join(temp_code).strip()
        submissions[temp_pid] = {
            "code": code,
            "updated_at": now,
            "uploader_ip": uploader_ip
        }
        count += 1

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


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True, port=5000)
