from flask import Flask, render_template, request, redirect, url_for, flash, current_app, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os, subprocess, uuid, yaml

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY") or "dev-secret"
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "sqlite:///cloud_workspaces.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", os.path.join(os.getcwd(), "uploads"))
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024


db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    workspaces = db.relationship("Workspace", backref="owner", lazy=True)

class Workspace(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    yaml_filename = db.Column(db.String(128), nullable=False)
    env_filename = db.Column(db.String(128), nullable=True)  # NEW
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(32), default="stopped")
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except Exception:
        return None

with app.app_context():
    db.create_all()

@app.route("/auth/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        u, p = request.form["username"], request.form["password"]
        if User.query.filter_by(username=u).first():
            flash("Username exists", "danger")
            return redirect(url_for("register"))
        user = User(username=u, password_hash=generate_password_hash(p))
        db.session.add(user)
        db.session.commit()
        flash("Registered!", "success")
        return redirect(url_for("login"))
    return render_template("login.html", register=True)

@app.route("/auth/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u, p = request.form["username"], request.form["password"]
        user = User.query.filter_by(username=u).first()
        if user and check_password_hash(user.password_hash, p):
            login_user(user)
            return redirect(url_for("dashboard"))
        flash("Invalid", "danger")
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

@app.route("/dashboard")
@login_required
def dashboard():
    user_workspaces = Workspace.query.filter_by(user_id=current_user.id).all()

    for ws in user_workspaces:
        if not getattr(ws, "yaml_filename", None):
            continue

        path = os.path.join(current_app.config["UPLOAD_FOLDER"], ws.yaml_filename)
        if not os.path.exists(path):
            if ws.status != "stopped":
                ws.status = "stopped"
                db.session.commit()
            continue

        project_name = f"workspace_{ws.id}"
        try:
            result = subprocess.run(
                ["docker-compose", "-p", project_name, "-f", path, "ps", "-q"],
                capture_output=True, text=True,
                cwd=os.path.dirname(path)
            )
            is_running = (result.returncode == 0 and result.stdout.strip() != "")
            new_status = "running" if is_running else "stopped"
            if ws.status != new_status:
                ws.status = new_status
                db.session.commit()
        except Exception as e:
            current_app.logger.error(f"Error checking status for {ws.name}: {str(e)}")
            if ws.status != "stopped":
                ws.status = "stopped"
                db.session.commit()

    workspaces = Workspace.query.filter_by(user_id=current_user.id).all()
    return render_template("dashboard.html", workspaces=workspaces)

@app.route("/workspace/create", methods=["GET", "POST"])
@login_required
def create_workspace():
    if request.method == "POST":
        name = request.form["name"]
        compose_file = request.files.get("yaml_file")
        env_file = request.files.get("env_file")

        if not compose_file:
            flash("YAML file required", "danger")
            return redirect(url_for("create_workspace"))

        # Save compose file
        compose_filename = f"{uuid.uuid4()}_{compose_file.filename}"
        os.makedirs(current_app.config["UPLOAD_FOLDER"], exist_ok=True)
        compose_path = os.path.join(current_app.config["UPLOAD_FOLDER"], compose_filename)
        compose_file.save(compose_path)

        env_filename = None
        ws = Workspace(
            name=name,
            yaml_filename=compose_filename,
            user_id=current_user.id
        )
        db.session.add(ws)
        db.session.commit()  # ✅ Save first to get ws.id

        if env_file:
            env_filename = f"{uuid.uuid4()}_{env_file.filename}"
            env_path = os.path.join(current_app.config["UPLOAD_FOLDER"], env_filename)
            env_file.save(env_path)
            ws.env_filename = env_filename
            db.session.commit()

            # Use ws.id to create build folder
            build_dir = os.path.join(
                current_app.config["UPLOAD_FOLDER"],
                f"build_{ws.id}"
            )
            os.makedirs(build_dir, exist_ok=True)

            # Write Dockerfile with conda setup
            with open(os.path.join(build_dir, "Dockerfile"), "w") as df:
                df.write("""FROM codercom/code-server:latest

# Install system dependencies
USER root
RUN apt-get update -y && \
    apt-get install -y --no-install-recommends wget bzip2 ca-certificates curl git && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Install Miniconda
RUN wget https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh -O miniconda.sh && \
    bash miniconda.sh -b -p /opt/conda && \
    rm miniconda.sh

ENV PATH=/opt/conda/bin:$PATH

# Copy environment.yml and create conda environment
COPY environment.yml /tmp/environment.yml

# Accept Anaconda Terms of Service before installing
RUN conda tos accept --override-channels --channel https://repo.anaconda.com/pkgs/main && \
    conda tos accept --override-channels --channel https://repo.anaconda.com/pkgs/r

RUN conda env create -f /tmp/environment.yml -n workspace_env && \
    conda clean -afy

# Activate environment by default
SHELL ["/bin/bash", "-lc"]
RUN echo "source /opt/conda/etc/profile.d/conda.sh && conda activate workspace_env" >> /home/coder/.bashrc

USER coder
WORKDIR /home/coder/project
""")

            import shutil
            shutil.copy(env_path, os.path.join(build_dir, "environment.yml"))

        flash("Workspace created successfully", "success")
        return redirect(url_for("dashboard"))

    return render_template("workspace.html")

@app.route("/workspace/run/<int:id>")
@login_required
def run_workspace(id):
    ws = db.session.get(Workspace, id)
    if ws is None:
        abort(404)
    if ws.user_id != current_user.id:
        flash("Access denied", "danger")
        return redirect(url_for("dashboard"))

    path = os.path.join(current_app.config["UPLOAD_FOLDER"], ws.yaml_filename)
    if not os.path.exists(path):
        flash("Workspace file not found", "danger")
        return redirect(url_for("dashboard"))

    project_name = f"workspace_{ws.id}"

    # 🔹 Add this block before subprocess.run
    if ws.env_filename:
        build_dir = os.path.join(
            current_app.config["UPLOAD_FOLDER"],
            f"build_{ws.id}"
        )
        patch_compose_with_build(path, build_dir)

    try:
        result = subprocess.run(
            ["docker-compose", "-p", project_name, "-f", path, "up", "-d"],
            capture_output=True, text=True, timeout=600,
            cwd=os.path.dirname(path)
        )
        if result.returncode == 0:
            ws.status = "running"
            db.session.commit()
            flash("Workspace is running", "success")
        else:
            current_app.logger.error(f"docker-compose up failed: {result.stderr}")
            flash(f"Failed: {result.stderr}", "danger")
    except subprocess.TimeoutExpired:
        flash("Timeout starting workspace", "warning")
    except Exception as e:
        current_app.logger.error(f"Error starting workspace {ws.name}: {e}")
        flash(f"Error: {str(e)}", "danger")

    return redirect(url_for("dashboard"))

@app.route("/workspace/stop/<int:id>")
@login_required
def stop_workspace(id):
    ws = db.session.get(Workspace, id)
    if ws is None:
        abort(404)
    if ws.user_id != current_user.id:
        flash("Access denied", "danger")
        return redirect(url_for("dashboard"))

    path = os.path.join(current_app.config["UPLOAD_FOLDER"], ws.yaml_filename)
    if not os.path.exists(path):
        flash("Workspace file not found", "danger")
        return redirect(url_for("dashboard"))

    project_name = f"workspace_{ws.id}"
    try:
        result = subprocess.run(
            ["docker-compose", "-p", project_name, "-f", path, "down"],
            capture_output=True, text=True, timeout=60,
            cwd=os.path.dirname(path)
        )
        if result.returncode == 0:
            ws.status = "stopped"
            db.session.commit()
            flash("Workspace stopped", "info")
        else:
            current_app.logger.error(f"docker-compose down failed: {result.stderr}")
            flash(f"Failed: {result.stderr}", "danger")
    except subprocess.TimeoutExpired:
        flash("Timeout stopping workspace", "warning")
    except Exception as e:
        current_app.logger.error(f"Error stopping workspace {ws.name}: {e}")
        flash(f"Error: {str(e)}", "danger")

    return redirect(url_for("dashboard"))


@app.route("/workspace/delete/<int:id>")
@login_required
def delete_workspace(id):
    ws = db.session.get(Workspace, id)
    if ws is None:
        abort(404)
    try:
        os.remove(os.path.join(current_app.config["UPLOAD_FOLDER"], ws.yaml_filename))
    except Exception:
        pass
    db.session.delete(ws)
    db.session.commit()
    flash("Workspace deleted", "warning")
    return redirect(url_for("dashboard"))

@app.route("/workspace/refresh-status/<int:id>")
@login_required
def refresh_workspace_status(id):
    ws = db.session.get(Workspace, id)
    if ws is None:
        abort(404)
    if ws.user_id != current_user.id:
        flash("Access denied", "danger")
        return redirect(url_for("dashboard"))

    path = os.path.join(current_app.config["UPLOAD_FOLDER"], ws.yaml_filename)
    if not os.path.exists(path):
        flash("Workspace file not found", "danger")
        return redirect(url_for("dashboard"))

    project_name = f"workspace_{ws.id}"
    try:
        result = subprocess.run(
            ["docker-compose", "-p", project_name, "-f", path, "ps", "-q"],
            capture_output=True, text=True, cwd=os.path.dirname(path)
        )
        ws.status = "running" if (result.returncode == 0 and result.stdout.strip()) else "stopped"
        db.session.commit()
        flash(f"Workspace is {ws.status}", "info")
    except Exception as e:
        current_app.logger.error(f"Error checking status for {ws.name}: {e}")
        flash(f"Error checking status: {str(e)}", "danger")

    return redirect(url_for("dashboard"))

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

@app.route("/workspace/cost-comparison/<int:id>")
@login_required
def cost_comparison(id):
    ws = db.session.get(Workspace, id)
    if ws is None:
        abort(404)
    if ws.user_id != current_user.id:
        flash("Access denied", "danger")
        return redirect(url_for("dashboard"))
    path = os.path.join(current_app.config["UPLOAD_FOLDER"], ws.yaml_filename)
    if not os.path.exists(path):
        flash("Workspace file not found", "danger")
        return redirect(url_for("dashboard"))
    resources = analyze_docker_compose_resources(path)
    cost_data = calculate_cloud_costs(resources)
    return render_template("cost_comparison.html",
                           workspace=ws, resources=resources, cost_data=cost_data)

def patch_compose_with_build(compose_path, build_dir):
    import yaml
    with open(compose_path) as f:
        data = yaml.safe_load(f)

    for svc, cfg in data.get("services", {}).items():
        if "code" in svc or "code-server" in str(cfg.get("image", "")):
            cfg.pop("image", None)
            cfg["build"] = build_dir

    with open(compose_path, "w") as f:
        yaml.safe_dump(data, f)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000, use_reloader=True)