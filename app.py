# app.py — MongoDB (Atlas) version
import os
import subprocess
import uuid
import yaml
import shutil
from datetime import datetime
from types import SimpleNamespace

from flask import Flask, render_template, request, redirect, url_for, flash, current_app, abort
from flask_pymongo import PyMongo
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from bson.objectid import ObjectId

# ----------------- CONFIG -----------------
class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY") or "dev-secret"
    MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017/cloud_workspace")
    UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", os.path.join(os.getcwd(), "uploads"))
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024

app = Flask(__name__)
app.config.from_object(Config)

# ----------------- MONGO & LOGIN -----------------
mongo = PyMongo(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# lightweight user wrapper for Flask-Login
class MongoUser(UserMixin):
    def __init__(self, doc):
        self.doc = doc
        self.id = str(doc["_id"])
        self.username = doc.get("username")

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

# Ensure unique index on username
with app.app_context():
    try:
        mongo.db.users.create_index("username", unique=True)
    except Exception:
        pass

# ----------------- AUTH -----------------
@app.route("/auth/register", methods=["GET", "POST"])
def register():
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
    if request.method == "POST":
        u = request.form.get("username", "").strip()
        p = request.form.get("password", "")
        user_doc = mongo.db.users.find_one({"username": u})
        if user_doc and check_password_hash(user_doc.get("password_hash", ""), p):
            login_user(MongoUser(user_doc))
            return redirect(url_for("dashboard"))
        flash("Invalid username or password", "danger")
    return render_template("login.html", register=False)

@app.route("/auth/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out", "info")
    return redirect(url_for("login"))

@app.route("/")
def home():
    return render_template("login.html", register=False)

# ----------------- DASHBOARD -----------------
@app.route("/dashboard")
@login_required
def dashboard():
    # fetch workspaces for the current user and convert to simple objects so templates can use ws.id
    cursor = mongo.db.workspaces.find({"user_id": current_user.get_id()})
    workspaces = []
    upload_folder = current_app.config["UPLOAD_FOLDER"]
    os.makedirs(upload_folder, exist_ok=True)

    for ws_doc in cursor:
        ws_obj = SimpleNamespace(
            id=str(ws_doc["_id"]),
            name=ws_doc.get("name"),
            yaml_filename=ws_doc.get("yaml_filename"),
            env_filename=ws_doc.get("env_filename"),
            status=ws_doc.get("status", "stopped"),
            created_at=ws_doc.get("created_at")
        )

        # check file presence & docker-compose status
        if not ws_obj.yaml_filename:
            workspaces.append(ws_obj)
            continue

        path = os.path.join(upload_folder, ws_obj.yaml_filename)
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

        compose_filename = f"{uuid.uuid4()}_{compose_file.filename}"
        compose_path = os.path.join(upload_folder, compose_filename)
        compose_file.save(compose_path)

        ws_doc = {
            "name": name,
            "yaml_filename": compose_filename,
            "env_filename": None,
            "created_at": datetime.utcnow(),
            "status": "stopped",
            "user_id": current_user.get_id()
        }
        res = mongo.db.workspaces.insert_one(ws_doc)
        ws_id_str = str(res.inserted_id)

        if env_file:
            env_filename = f"{uuid.uuid4()}_{env_file.filename}"
            env_path = os.path.join(upload_folder, env_filename)
            env_file.save(env_path)
            mongo.db.workspaces.update_one({"_id": ObjectId(ws_id_str)}, {"$set": {"env_filename": env_filename}})

            # prepare build dir and Dockerfile
            build_dir = os.path.join(upload_folder, f"build_{ws_id_str}")
            os.makedirs(build_dir, exist_ok=True)
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
            shutil.copy(env_path, os.path.join(build_dir, "environment.yml"))

        flash("Workspace created successfully", "success")
        return redirect(url_for("dashboard"))

    return render_template("workspace.html")

# ----------------- RUN / STOP / DELETE / REFRESH -----------------
def _get_workspace_or_404(ws_id):
    try:
        doc = mongo.db.workspaces.find_one({"_id": ObjectId(ws_id)})
        if not doc:
            abort(404)
        return doc
    except Exception:
        abort(404)

@app.route("/workspace/run/<string:id>")
@login_required
def run_workspace(id):
    ws = _get_workspace_or_404(id)
    if ws["user_id"] != current_user.get_id():
        flash("Access denied", "danger")
        return redirect(url_for("dashboard"))

    path = os.path.join(current_app.config["UPLOAD_FOLDER"], ws["yaml_filename"])
    if not os.path.exists(path):
        flash("Workspace file not found", "danger")
        return redirect(url_for("dashboard"))

    project_name = f"workspace_{id}"

    if ws.get("env_filename"):
        build_dir = os.path.join(current_app.config["UPLOAD_FOLDER"], f"build_{id}")
        patch_compose_with_build(path, build_dir)

    try:
        result = subprocess.run(
            ["docker-compose", "-p", project_name, "-f", path, "up", "-d"],
            capture_output=True, text=True, timeout=600,
            cwd=os.path.dirname(path)
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

    path = os.path.join(current_app.config["UPLOAD_FOLDER"], ws["yaml_filename"])
    if not os.path.exists(path):
        flash("Workspace file not found", "danger")
        return redirect(url_for("dashboard"))

    project_name = f"workspace_{id}"
    try:
        result = subprocess.run(
            ["docker-compose", "-p", project_name, "-f", path, "down"],
            capture_output=True, text=True, timeout=60,
            cwd=os.path.dirname(path)
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
    try:
        os.remove(os.path.join(current_app.config["UPLOAD_FOLDER"], ws["yaml_filename"]))
    except Exception:
        pass
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

    path = os.path.join(current_app.config["UPLOAD_FOLDER"], ws["yaml_filename"])
    if not os.path.exists(path):
        flash("Workspace file not found", "danger")
        return redirect(url_for("dashboard"))

    project_name = f"workspace_{id}"
    try:
        result = subprocess.run(
            ["docker-compose", "-p", project_name, "-f", path, "ps", "-q"],
            capture_output=True, text=True, cwd=os.path.dirname(path)
        )
        new_status = "running" if (result.returncode == 0 and result.stdout.strip()) else "stopped"
        mongo.db.workspaces.update_one({"_id": ObjectId(id)}, {"$set": {"status": new_status}})
        flash(f"Workspace is {new_status}", "info")
    except Exception as e:
        current_app.logger.error(f"Error checking status for {ws.get('name')}: {e}")
        flash(f"Error checking status: {str(e)}", "danger")

    return redirect(url_for("dashboard"))

# ----------------- COST ANALYSIS (unchanged logic) -----------------
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
                        cpu = float(limits["cpus"])
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
    path = os.path.join(current_app.config["UPLOAD_FOLDER"], ws["yaml_filename"])
    if not os.path.exists(path):
        flash("Workspace file not found", "danger")
        return redirect(url_for("dashboard"))
    resources = analyze_docker_compose_resources(path)
    cost_data = calculate_cloud_costs(resources)
    # convert ws to simple object for template convenience
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
    app.run(debug=True, host="0.0.0.0", port=5000)
