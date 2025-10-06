# app.py — modified to support Firebase Auth + Firebase Storage (or fall back to local)
import os
import subprocess
import uuid
import yaml
import shutil
import json
from datetime import datetime
from types import SimpleNamespace

from flask import Flask, render_template, request, redirect, url_for, flash, current_app, abort
from flask_pymongo import PyMongo
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from bson.objectid import ObjectId

# Optional: CORS if frontend and backend are on different domains
from flask_cors import CORS

# --- optional Firebase Admin imports ---
try:
    import firebase_admin
    from firebase_admin import credentials as fb_credentials, auth as fb_auth, storage as fb_storage
except Exception:
    firebase_admin = None
    fb_credentials = None
    fb_auth = None
    fb_storage = None

# ----------------- CONFIG -----------------
class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY") or "dev-secret"
    MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017/cloud_workspace")
    UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", os.path.join(os.getcwd(), "uploads"))
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024

    # New:
    AUTH_MODE = os.environ.get("AUTH_MODE", "firebase")  # 'local' or 'firebase'
    FIREBASE_SERVICE_ACCOUNT = os.environ.get("FIREBASE_SERVICE_ACCOUNT")  # JSON string or path
    FIREBASE_STORAGE_BUCKET = os.environ.get("FIREBASE_STORAGE_BUCKET")    # e.g. myproj.appspot.com
    ENABLE_LOCAL_RUNNER = os.environ.get("ENABLE_LOCAL_RUNNER", "true").lower() == "true"

app = Flask(__name__)
app.config.from_object(Config)
CORS(app)  # allow cross-origin from frontend if hosted separately

# ----------------- MONGO & LOGIN -----------------
mongo = PyMongo(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# lightweight user wrapper for Flask-Login (works with both local and firebase-backed users stored in Mongo)
class MongoUser(UserMixin):
    def __init__(self, doc):
        self.doc = doc
        self.id = str(doc["_id"])
        self.username = doc.get("username") or doc.get("email") or doc.get("firebase_uid")

    def get_id(self):
        return self.id

@login_manager.user_loader
def load_user(user_id):
    try:
        doc = mongo.db.users.find_one({"_id": ObjectId(user_id)})
        if doc:
            return MongoUser(doc)
    except Exception:
        return None

# Ensure unique index on username (best-effort)
with app.app_context():
    try:
        mongo.db.users.create_index("username", unique=True)
    except Exception:
        pass

# ----------------- FIREBASE ADMIN (optional) -----------------
fb_bucket = None

def init_firebase_admin():
    """Initialize firebase_admin if configured."""
    global fb_bucket
    if not firebase_admin:
        print("firebase_admin not installed (skipping firebase init).")
        return
    sa = app.config.get("FIREBASE_SERVICE_ACCOUNT")
    bucket_name = app.config.get("FIREBASE_STORAGE_BUCKET")
    if not sa and not os.environ.get("GOOGLE_APPLICATION_CREDENTIALS"):
        print("No Firebase service account provided; skipping firebase init.")
        return
    try:
        # If sa is JSON string
        if sa and sa.strip().startswith("{"):
            sa_dict = json.loads(sa)
            cred = fb_credentials.Certificate(sa_dict)
        elif sa and os.path.exists(sa):
            cred = fb_credentials.Certificate(sa)
        else:
            # fallback to ADC
            cred = fb_credentials.ApplicationDefault()
        firebase_admin.initialize_app(cred, {"storageBucket": bucket_name})
        fb_bucket = fb_storage.bucket()
        print("Firebase Admin initialized. Bucket:", fb_bucket.name)
    except Exception as e:
        print("Firebase Admin initialization failed:", e)
        fb_bucket = None

# Initialize at startup if configured
with app.app_context():
    if app.config["AUTH_MODE"] == "firebase" or app.config.get("FIREBASE_SERVICE_ACCOUNT"):
        init_firebase_admin()

# ----------------- FIREBASE STORAGE HELPERS -----------------
def upload_fileobj_to_storage(file_obj, storage_path):
    """Uploads werkzeug.FileStorage (request.files['...']) to Firebase Storage at storage_path."""
    if fb_bucket is None:
        raise RuntimeError("Firebase storage not initialized")
    blob = fb_bucket.blob(storage_path)
    file_obj.stream.seek(0)
    blob.upload_from_file(file_obj.stream, content_type=file_obj.mimetype)
    return storage_path

def upload_localfile_to_storage(local_path, storage_path):
    if fb_bucket is None:
        raise RuntimeError("Firebase storage not initialized")
    blob = fb_bucket.blob(storage_path)
    blob.upload_from_filename(local_path)
    return storage_path

def download_storage_to_local(storage_path, local_path):
    """Download a blob to a local path (create dirs as needed)."""
    if fb_bucket is None:
        raise RuntimeError("Firebase storage not initialized")
    blob = fb_bucket.blob(storage_path)
    os.makedirs(os.path.dirname(local_path), exist_ok=True)
    blob.download_to_filename(local_path)
    return local_path

def delete_storage_blob(storage_path):
    if fb_bucket is None:
        raise RuntimeError("Firebase storage not initialized")
    blob = fb_bucket.blob(storage_path)
    blob.delete()

# ----------------- AUTH (local + firebase support) -----------------
@app.route("/auth/register", methods=["GET", "POST"])
def register():
    # keep local register for dev/test if AUTH_MODE==local
    if app.config["AUTH_MODE"] != "local":
        flash("Registration is handled by Firebase when AUTH_MODE=firebase. Use the frontend Firebase UI.", "warning")
        return redirect(url_for("login"))

    if request.method == "POST":
        u = request.form.get("username", "").strip()
        p = request.form.get("password", "")
        cp = request.form.get("confirm_password", "")
        if not u or not p:
            flash("Provide username and password", "danger")
            return redirect(url_for("register"))
        if p != cp:
            flash("Passwords do not match", "danger")
            return redirect(url_for("register"))
        if mongo.db.users.find_one({"username": u}):
            flash("Username exists", "danger")
            return redirect(url_for("register"))

        pw_hash = generate_password_hash(p)
        mongo.db.users.insert_one({
            "username": u,
            "password_hash": pw_hash,
            "created_at": datetime.utcnow()
        })
        flash("Registered! Please log in.", "success")
        return redirect(url_for("login"))
    return render_template("login.html", register=True)

@app.route("/auth/login", methods=["GET", "POST"])
def login():
    # local login form behavior retained for dev
    if app.config["AUTH_MODE"] != "local":
        flash("Use Firebase authentication on the frontend when AUTH_MODE=firebase.", "info")
        return render_template("login.html", register=False)

    if request.method == "POST":
        u = request.form.get("username", "").strip()
        p = request.form.get("password", "")
        user_doc = mongo.db.users.find_one({"username": u})
        if user_doc and check_password_hash(user_doc.get("password_hash", ""), p):
            login_user(MongoUser(user_doc))
            return redirect(url_for("dashboard"))
        flash("Invalid username or password", "danger")
    return render_template("login.html", register=False)

@app.route("/auth/token-login", methods=["POST"])
def token_login():
    """
    Backend endpoint to accept Firebase ID token from the frontend.
    Frontend should POST with Authorization: Bearer <idToken> or form field idToken.
    """
    if app.config["AUTH_MODE"] != "firebase":
        flash("Token-login only available when AUTH_MODE=firebase", "danger")
        return redirect(url_for("login"))

    token = None
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header.split("Bearer ", 1)[1].strip()
    else:
        token = request.form.get("idToken") or request.json.get("idToken") if request.is_json else None

    if not token:
        flash("Missing ID token", "danger")
        return redirect(url_for("login"))

    try:
        decoded = fb_auth.verify_id_token(token)
        uid = decoded.get("uid")
        email = decoded.get("email")
    except Exception as e:
        current_app.logger.error(f"Token verification failed: {e}")
        flash("Invalid token", "danger")
        return redirect(url_for("login"))

    # create or find mongo user record mapped to this Firebase UID
    user_doc = mongo.db.users.find_one({"firebase_uid": uid})
    if not user_doc:
        new_doc = {
            "firebase_uid": uid,
            "username": email or uid,
            "email": email,
            "created_at": datetime.utcnow()
        }
        res = mongo.db.users.insert_one(new_doc)
        user_doc = mongo.db.users.find_one({"_id": res.inserted_id})

    login_user(MongoUser(user_doc))
    return redirect(url_for("dashboard"))

@app.route("/auth/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out", "info")
    return redirect(url_for("login"))

@app.route("/")
def home():
    return render_template("login.html", register=(app.config["AUTH_MODE"] == "local"))

# ----------------- DASHBOARD -----------------
@app.route("/dashboard")
@login_required
def dashboard():
    cursor = mongo.db.workspaces.find({"user_id": current_user.get_id()})
    workspaces = []
    upload_folder = current_app.config["UPLOAD_FOLDER"]
    os.makedirs(upload_folder, exist_ok=True)

    for ws_doc in cursor:
        ws_obj = SimpleNamespace(
            id=str(ws_doc["_id"]),
            name=ws_doc.get("name"),
            yaml_storage_path=ws_doc.get("yaml_storage_path"),
            env_storage_path=ws_doc.get("env_storage_path"),
            yaml_filename=ws_doc.get("yaml_filename"),  # fallback for older local entries
            env_filename=ws_doc.get("env_filename"),
            status=ws_doc.get("status", "stopped"),
            created_at=ws_doc.get("created_at")
        )

        # If local runner is enabled, ensure local copy exists and check docker-compose status
        if app.config["ENABLE_LOCAL_RUNNER"]:
            # compute local path for the YAML (download from storage if needed)
            if ws_obj.yaml_storage_path:
                local_yaml_name = os.path.basename(ws_obj.yaml_storage_path)
                local_yaml_path = os.path.join(upload_folder, local_yaml_name)
                if not os.path.exists(local_yaml_path):
                    try:
                        download_storage_to_local(ws_obj.yaml_storage_path, local_yaml_path)
                    except Exception as e:
                        current_app.logger.error(f"Failed to download yaml for ws {ws_obj.name}: {e}")

                path = local_yaml_path
            elif ws_obj.yaml_filename:
                path = os.path.join(upload_folder, ws_obj.yaml_filename)
            else:
                workspaces.append(ws_obj)
                continue

            if not os.path.exists(path):
                if ws_obj.status != "stopped":
                    mongo.db.workspaces.update_one({"_id": ObjectId(ws_obj.id)}, {"$set": {"status": "stopped"}})
                    ws_obj.status = "stopped"
                workspaces.append(ws_obj)
                continue

            project_name = f"workspace_{ws_obj.id}"
            try:
                result = subprocess.run(
                    ["docker-compose", "-p", project_name, "-f", path, "ps", "-q"],
                    capture_output=True, text=True, cwd=os.path.dirname(path)
                )
                is_running = (result.returncode == 0 and result.stdout.strip() != "")
                new_status = "running" if is_running else "stopped"
                if new_status != ws_obj.status:
                    mongo.db.workspaces.update_one({"_id": ObjectId(ws_obj.id)}, {"$set": {"status": new_status}})
                    ws_obj.status = new_status
            except Exception as e:
                current_app.logger.error(f"Status check error for {ws_obj.name}: {e}")
                if ws_obj.status != "stopped":
                    mongo.db.workspaces.update_one({"_id": ObjectId(ws_obj.id)}, {"$set": {"status": "stopped"}})
                    ws_obj.status = "stopped"

        # If local runner not enabled, we cannot check docker status in cloud — leave as is
        workspaces.append(ws_obj)

    return render_template("dashboard.html", workspaces=workspaces)

# ----------------- WORKSPACE CREATE -----------------
@app.route("/workspace/create", methods=["GET", "POST"])
@login_required
def create_workspace():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        compose_file = request.files.get("yaml_file")
        env_file = request.files.get("env_file")

        if not name or not compose_file:
            flash("Name and YAML file are required", "danger")
            return redirect(url_for("create_workspace"))

        upload_folder = current_app.config["UPLOAD_FOLDER"]
        os.makedirs(upload_folder, exist_ok=True)

        ws_uuid = str(uuid.uuid4())
        compose_storage_path = f"workspaces/{ws_uuid}_{compose_file.filename}"

        # Upload compose file to Firebase Storage (or save locally if Firebase not configured)
        if fb_bucket:
            upload_fileobj_to_storage(compose_file, compose_storage_path)
            yaml_storage_path = compose_storage_path
            yaml_local_name = os.path.basename(compose_storage_path)
        else:
            # fallback: save locally
            yaml_local_name = f"{ws_uuid}_{compose_file.filename}"
            compose_local_path = os.path.join(upload_folder, yaml_local_name)
            compose_file.save(compose_local_path)
            yaml_storage_path = None

        ws_doc = {
            "name": name,
            "yaml_storage_path": yaml_storage_path,
            "yaml_filename": yaml_local_name if not yaml_storage_path else None,
            "env_storage_path": None,
            "env_filename": None,
            "created_at": datetime.utcnow(),
            "status": "stopped",
            "user_id": current_user.get_id()
        }
        res = mongo.db.workspaces.insert_one(ws_doc)
        ws_id_str = str(res.inserted_id)

        # If env_file present, upload and prepare build dir (for local docker runner)
        if env_file:
            env_storage_path = f"workspaces/{ws_uuid}_{env_file.filename}"
            if fb_bucket:
                # save locally temporarily for build dir, and upload to storage
                local_env_tmp = os.path.join(upload_folder, f"{ws_uuid}_{env_file.filename}")
                env_file.save(local_env_tmp)
                upload_localfile_to_storage(local_env_tmp, env_storage_path)
                env_local_name = os.path.basename(env_storage_path)
            else:
                env_local_name = f"{ws_uuid}_{env_file.filename}"
                local_env_tmp = os.path.join(upload_folder, env_local_name)
                env_file.save(local_env_tmp)
                env_storage_path = None

            # update workspace doc with env paths
            mongo.db.workspaces.update_one({"_id": ObjectId(ws_id_str)}, {"$set": {"env_storage_path": env_storage_path, "env_filename": env_local_name}})

            # prepare build dir and Dockerfile for local runner (only if runner enabled)
            if app.config["ENABLE_LOCAL_RUNNER"]:
                build_dir = os.path.join(upload_folder, f"build_{ws_id_str}")
                os.makedirs(build_dir, exist_ok=True)
                # ensure we have local copy of environment.yml in build_dir
                local_env_for_build = os.path.join(build_dir, "environment.yml")
                try:
                    if env_storage_path and fb_bucket:
                        # download from storage
                        download_storage_to_local(env_storage_path, local_env_for_build)
                    else:
                        # copy the uploaded temp
                        shutil.copy(local_env_tmp, local_env_for_build)
                except Exception as e:
                    current_app.logger.error(f"Failed to prepare build dir for ws {name}: {e}")

                dockerfile_path = os.path.join(build_dir, "Dockerfile")
                with open(dockerfile_path, "w") as df:
                    df.write("""FROM codercom/code-server:latest

USER root
RUN apt-get update -y && apt-get install -y --no-install-recommends wget bzip2 ca-certificates curl git && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN wget https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh -O miniconda.sh && \
    bash miniconda.sh -b -p /opt/conda && rm miniconda.sh

ENV PATH=/opt/conda/bin:$PATH

COPY environment.yml /tmp/environment.yml

RUN conda tos accept --override-channels --channel https://repo.anaconda.com/pkgs/main && \
    conda tos accept --override-channels --channel https://repo.anaconda.com/pkgs/r

RUN conda env create -f /tmp/environment.yml -n workspace_env && conda clean -afy

SHELL ["/bin/bash", "-lc"]
RUN echo "source /opt/conda/etc/profile.d/conda.sh && conda activate workspace_env" >> /home/coder/.bashrc

USER coder
WORKDIR /home/coder/project
""")

        flash("Workspace created successfully", "success")
        return redirect(url_for("dashboard"))

    return render_template("workspace.html")

# ----------------- HELPERS: get workspace doc -----------------
def _get_workspace_or_404(ws_id):
    try:
        doc = mongo.db.workspaces.find_one({"_id": ObjectId(ws_id)})
        if not doc:
            abort(404)
        return doc
    except Exception:
        abort(404)

# ----------------- RUN / STOP / DELETE / REFRESH -----------------
@app.route("/workspace/run/<string:id>")
@login_required
def run_workspace(id):
    ws = _get_workspace_or_404(id)
    if ws["user_id"] != current_user.get_id():
        flash("Access denied", "danger")
        return redirect(url_for("dashboard"))

    # local runner must be enabled to actually run docker-compose
    if not app.config["ENABLE_LOCAL_RUNNER"]:
        flash("Running workspaces is disabled on this deployment (local runner only).", "warning")
        return redirect(url_for("dashboard"))

    # ensure local compose path exists (download if necessary)
    upload_folder = current_app.config["UPLOAD_FOLDER"]
    if ws.get("yaml_storage_path"):
        local_name = os.path.basename(ws["yaml_storage_path"])
        local_path = os.path.join(upload_folder, local_name)
        if not os.path.exists(local_path):
            try:
                download_storage_to_local(ws["yaml_storage_path"], local_path)
            except Exception as e:
                current_app.logger.error(f"Failed to download compose for run: {e}")
                flash("Workspace file not available locally", "danger")
                return redirect(url_for("dashboard"))
    elif ws.get("yaml_filename"):
        local_path = os.path.join(upload_folder, ws["yaml_filename"])
        if not os.path.exists(local_path):
            flash("Workspace file not found", "danger")
            return redirect(url_for("dashboard"))
    else:
        flash("Workspace file not found", "danger")
        return redirect(url_for("dashboard"))

    project_name = f"workspace_{id}"

    if ws.get("env_filename"):
        build_dir = os.path.join(upload_folder, f"build_{id}")
        patch_compose_with_build(local_path, build_dir)

    try:
        result = subprocess.run(
            ["docker-compose", "-p", project_name, "-f", local_path, "up", "-d"],
            capture_output=True, text=True, timeout=600,
            cwd=os.path.dirname(local_path)
        )
        if result.returncode == 0:
            mongo.db.workspaces.update_one({"_id": ObjectId(id)}, {"$set": {"status": "running"}})
            flash("Workspace is running", "success")
        else:
            current_app.logger.error(f"docker-compose up failed: {result.stderr}")
            flash(f"Failed: {result.stderr}", "danger")
    except subprocess.TimeoutExpired:
        flash("Timeout starting workspace", "warning")
    except Exception as e:
        current_app.logger.error(f"Error starting workspace {ws.get('name')}: {e}")
        flash(f"Error: {str(e)}", "danger")

    return redirect(url_for("dashboard"))

@app.route("/workspace/stop/<string:id>")
@login_required
def stop_workspace(id):
    ws = _get_workspace_or_404(id)
    if ws["user_id"] != current_user.get_id():
        flash("Access denied", "danger")
        return redirect(url_for("dashboard"))

    if not app.config["ENABLE_LOCAL_RUNNER"]:
        flash("Stopping workspaces is disabled on this deployment (local runner only).", "warning")
        return redirect(url_for("dashboard"))

    # ensure local compose path exists (download if necessary)
    upload_folder = current_app.config["UPLOAD_FOLDER"]
    if ws.get("yaml_storage_path"):
        local_name = os.path.basename(ws["yaml_storage_path"])
        local_path = os.path.join(upload_folder, local_name)
        if not os.path.exists(local_path):
            try:
                download_storage_to_local(ws["yaml_storage_path"], local_path)
            except Exception as e:
                current_app.logger.error(f"Failed to download compose for stop: {e}")
                flash("Workspace file not available locally", "danger")
                return redirect(url_for("dashboard"))
    elif ws.get("yaml_filename"):
        local_path = os.path.join(upload_folder, ws["yaml_filename"])
        if not os.path.exists(local_path):
            flash("Workspace file not found", "danger")
            return redirect(url_for("dashboard"))
    else:
        flash("Workspace file not found", "danger")
        return redirect(url_for("dashboard"))

    project_name = f"workspace_{id}"
    try:
        result = subprocess.run(
            ["docker-compose", "-p", project_name, "-f", local_path, "down"],
            capture_output=True, text=True, timeout=60,
            cwd=os.path.dirname(local_path)
        )
        if result.returncode == 0:
            mongo.db.workspaces.update_one({"_id": ObjectId(id)}, {"$set": {"status": "stopped"}})
            flash("Workspace stopped", "info")
        else:
            current_app.logger.error(f"docker-compose down failed: {result.stderr}")
            flash(f"Failed: {result.stderr}", "danger")
    except subprocess.TimeoutExpired:
        flash("Timeout stopping workspace", "warning")
    except Exception as e:
        current_app.logger.error(f"Error stopping workspace {ws.get('name')}: {e}")
        flash(f"Error: {str(e)}", "danger")

    return redirect(url_for("dashboard"))

@app.route("/workspace/delete/<string:id>", methods=["POST"])
@login_required
def delete_workspace(id):
    ws = _get_workspace_or_404(id)
    # Authorization
    if ws["user_id"] != current_user.get_id():
        flash("Access denied", "danger")
        return redirect(url_for("dashboard"))

    # delete local file(s) if exist
    try:
        if ws.get("yaml_filename"):
            try:
                os.remove(os.path.join(current_app.config["UPLOAD_FOLDER"], ws["yaml_filename"]))
            except Exception:
                pass
        if ws.get("env_filename"):
            try:
                os.remove(os.path.join(current_app.config["UPLOAD_FOLDER"], ws["env_filename"]))
            except Exception:
                pass
    except Exception:
        pass

    # delete from Firebase Storage if configured
    try:
        if ws.get("yaml_storage_path") and fb_bucket:
            delete_storage_blob(ws.get("yaml_storage_path"))
        if ws.get("env_storage_path") and fb_bucket:
            delete_storage_blob(ws.get("env_storage_path"))
    except Exception as e:
        current_app.logger.error(f"Error deleting storage blobs: {e}")

    # remove build dir if exists
    try:
        build_dir = os.path.join(current_app.config["UPLOAD_FOLDER"], f"build_{id}")
        if os.path.isdir(build_dir):
            shutil.rmtree(build_dir)
    except Exception:
        pass

    mongo.db.workspaces.delete_one({"_id": ObjectId(id)})
    flash("Workspace deleted", "warning")
    return redirect(url_for("dashboard"))

@app.route("/workspace/refresh-status/<string:id>")
@login_required
def refresh_workspace_status(id):
    ws = _get_workspace_or_404(id)
    if ws["user_id"] != current_user.get_id():
        flash("Access denied", "danger")
        return redirect(url_for("dashboard"))

    if not app.config["ENABLE_LOCAL_RUNNER"]:
        flash("Refreshing status is disabled on this deployment (local runner only).", "warning")
        return redirect(url_for("dashboard"))

    upload_folder = current_app.config["UPLOAD_FOLDER"]
    if ws.get("yaml_storage_path"):
        local_name = os.path.basename(ws["yaml_storage_path"])
        local_path = os.path.join(upload_folder, local_name)
        if not os.path.exists(local_path):
            try:
                download_storage_to_local(ws["yaml_storage_path"], local_path)
            except Exception as e:
                current_app.logger.error(f"Failed to download compose for refresh: {e}")
                flash("Workspace file not available locally", "danger")
                return redirect(url_for("dashboard"))
    elif ws.get("yaml_filename"):
        local_path = os.path.join(upload_folder, ws["yaml_filename"])
        if not os.path.exists(local_path):
            flash("Workspace file not found", "danger")
            return redirect(url_for("dashboard"))
    else:
        flash("Workspace file not found", "danger")
        return redirect(url_for("dashboard"))

    project_name = f"workspace_{id}"
    try:
        result = subprocess.run(
            ["docker-compose", "-p", project_name, "-f", local_path, "ps", "-q"],
            capture_output=True, text=True, cwd=os.path.dirname(local_path)
        )
        new_status = "running" if (result.returncode == 0 and result.stdout.strip()) else "stopped"
        mongo.db.workspaces.update_one({"_id": ObjectId(id)}, {"$set": {"status": new_status}})
        flash(f"Workspace is {new_status}", "info")
    except Exception as e:
        current_app.logger.error(f"Error checking status for {ws.get('name')}: {e}")
        flash(f"Error checking status: {str(e)}", "danger")

    return redirect(url_for("dashboard"))

# ----------------- COST ANALYSIS (unchanged) -----------------
def analyze_docker_compose_resources(yaml_path):
    try:
        with open(yaml_path, "r") as file:
            compose_data = yaml.safe_load(file)
        total_cpu = total_memory = 0
        services = []
        if "services" in compose_data:
            for name, cfg in compose_data["services"].items():
                cpu = mem = 0
                if "deploy" in cfg and "resources" in cfg["deploy"]:
                    limits = cfg["deploy"]["resources"].get("limits", {})
                    if "cpus" in limits:
                        try:
                            cpu = float(limits["cpus"])
                        except Exception:
                            cpu = 0
                    if "memory" in limits:
                        m = limits["memory"]
                        if isinstance(m, str):
                            if m.endswith("G"): mem = float(m[:-1])
                            elif m.endswith("M"): mem = float(m[:-1]) / 1024
                            elif m.endswith("K"): mem = float(m[:-1]) / (1024*1024)
                cpu = cpu or 1.0
                mem = mem or 1.0
                total_cpu += cpu; total_memory += mem
                services.append({"name": name, "cpu": cpu, "memory": mem})
        return {
            "total_cpu": total_cpu,
            "total_memory": total_memory,
            "total_storage": len(services) * 10,
            "services": services
        }
    except Exception as e:
        current_app.logger.error(f"Error analyzing compose file: {str(e)}")
        return {"total_cpu": 2, "total_memory": 4, "total_storage": 20, "services": []}

def calculate_cloud_costs(resources):
    cpu, memory, storage = (
        resources["total_cpu"], resources["total_memory"], resources["total_storage"]
    )
    pricing = {
        "aws": {"ec2_t3_medium": {"cpu": 2, "memory": 4, "price": 0.0416},
                "ec2_t3_large": {"cpu": 2, "memory": 8, "price": 0.0832},
                "ec2_t3_xlarge": {"cpu": 4, "memory": 16, "price": 0.1664},
                "storage": 0.10, "name": "AWS"},
        "azure": {"b2s": {"cpu": 2, "memory": 4, "price": 0.0408},
                  "b2ms": {"cpu": 2, "memory": 8, "price": 0.0816},
                  "b4ms": {"cpu": 4, "memory": 16, "price": 0.1632},
                  "storage": 0.12, "name": "Azure"},
        "gcp": {"e2_medium": {"cpu": 2, "memory": 4, "price": 0.0335},
                "e2_standard_2": {"cpu": 2, "memory": 8, "price": 0.0670},
                "e2_standard_4": {"cpu": 4, "memory": 16, "price": 0.1340},
                "storage": 0.08, "name": "GCP"},
        "digitalocean": {"s_2vcpu_4gb": {"cpu": 2, "memory": 4, "price": 0.024},
                         "s_2vcpu_8gb": {"cpu": 2, "memory": 8, "price": 0.048},
                         "s_4vcpu_8gb": {"cpu": 4, "memory": 8, "price": 0.072},
                         "storage": 0.10, "name": "DigitalOcean"},
    }
    results = {}
    for provider, data in pricing.items():
        best = None
        for k, inst in data.items():
            if isinstance(inst, dict) and "cpu" in inst:
                if inst["cpu"] >= cpu and inst["memory"] >= memory:
                    if not best or inst["price"] < best["price"]:
                        best = inst
        if best:
            hourly = best["price"]
            monthly = hourly * 24 * 30
            total = monthly + data["storage"] * storage
            results[provider] = {
                "name": data["name"], "instance_type": best,
                "hourly_cost": hourly, "monthly_cost": monthly,
                "storage_cost": data["storage"] * storage,
                "total_monthly": total,
            }
    return results

@app.route("/workspace/cost-comparison/<string:id>")
@login_required
def cost_comparison(id):
    ws = _get_workspace_or_404(id)
    if ws["user_id"] != current_user.get_id():
        flash("Access denied", "danger")
        return redirect(url_for("dashboard"))
    # pick a local path if we can
    path = None
    upload_folder = current_app.config["UPLOAD_FOLDER"]
    if ws.get("yaml_storage_path"):
        local_name = os.path.basename(ws["yaml_storage_path"])
        local_path = os.path.join(upload_folder, local_name)
        if os.path.exists(local_path):
            path = local_path
        else:
            # try to download for local analysis
            try:
                download_storage_to_local(ws["yaml_storage_path"], local_path)
                path = local_path
            except Exception:
                path = None
    elif ws.get("yaml_filename"):
        path = os.path.join(upload_folder, ws.get("yaml_filename"))

    if not path or not os.path.exists(path):
        flash("Workspace file not available for analysis", "danger")
        return redirect(url_for("dashboard"))

    resources = analyze_docker_compose_resources(path)
    cost_data = calculate_cloud_costs(resources)
    ws_obj = SimpleNamespace(id=str(ws["_id"]), name=ws.get("name"), yaml_filename=ws.get("yaml_filename"),
                             env_filename=ws.get("env_filename"), status=ws.get("status"))
    return render_template("cost_comparison.html", workspace=ws_obj, resources=resources, cost_data=cost_data)

# ----------------- HELPER: patch compose -----------------
def patch_compose_with_build(compose_path, build_dir):
    import yaml as _yaml
    try:
        with open(compose_path) as f:
            data = _yaml.safe_load(f) or {}
        for svc, cfg in data.get("services", {}).items():
            if "code" in svc or "code-server" in str(cfg.get("image", "")):
                cfg.pop("image", None)
                cfg["build"] = build_dir
        with open(compose_path, "w") as f:
            _yaml.safe_dump(data, f)
    except Exception as e:
        current_app.logger.error(f"Error patching compose: {e}")

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
