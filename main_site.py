#!/usr/bin/env python3
import os
import json
import hashlib
import string
from functools import wraps
from datetime import datetime
from flask import (
    Flask, request, session, redirect, url_for,
    render_template_string, jsonify, send_file, abort, send_from_directory
)
import logging
import threading

# ---------- Configuration ----------
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin")  # default for easy testing
FLASK_SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "a-very-secret-key")  # default
# Do not raise here -- defaults help local testing and Gunicorn deployments.
# In production you may want to enforce env vars.

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_DIR = os.path.join(BASE_DIR, "configs")
os.makedirs(CONFIG_DIR, exist_ok=True)
try:
    os.chmod(CONFIG_DIR, 0o700)  # Restrict permissions (best-effort)
except OSError:
    pass

# Directory for persisting latest texts (shared by all workers)
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)
try:
    os.chmod(DATA_DIR, 0o700)
except OSError:
    pass  # best-effort

# ---------- Logging ----------
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# ---------- Flask App ----------
app = Flask(__name__)
app.secret_key = FLASK_SECRET_KEY
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# ---------- Data Store (thread-safe + file-backed) ----------
RECEIVED_TEXTS = {}  # in-memory cache {name: {"en":..., "sw":..., "zh":...}}
RECEIVED_TEXTS_LOCK = threading.Lock()

def _name_to_filename(name: str) -> str:
    """Return a safe filename for a given name (sha256)."""
    h = hashlib.sha256(name.encode("utf-8")).hexdigest()
    return f"{h}.latest.json"

def _latest_path_for_name(name: str) -> str:
    return os.path.join(DATA_DIR, _name_to_filename(name))

def save_latest_text_file(name: str, texts: dict):
    """Atomically save the latest texts for a name to disk (JSON)."""
    path = _latest_path_for_name(name)
    tmp = path + ".tmp"
    try:
        txt = json.dumps(texts or {}, indent=2, ensure_ascii=False) + "\n"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(txt)
            fh.flush()
            try:
                os.fsync(fh.fileno())
            except OSError:
                pass
        os.replace(tmp, path)  # atomic on POSIX
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    finally:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass

def load_latest_text_file(name: str) -> dict:
    """Load the latest texts for a name from disk. Returns {} if not present or invalid."""
    path = _latest_path_for_name(name)
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
            if isinstance(data, dict):
                return {k: v for k, v in data.items()}
    except (OSError, json.JSONDecodeError) as e:
        logging.warning(f"Could not load latest text file for {name}: {e}")
    return {}

# ---------- Helper Functions ----------
def is_hex_64(s: str) -> bool:
    """Checks if a string is a 64-character hexadecimal string."""
    s = (s or "").strip()
    return len(s) == 64 and all(c in string.hexdigits for c in s)

def compute_hash(identifier: str) -> str:
    """Computes the SHA-256 hash of an identifier (license key or string)."""
    if not identifier:
        raise ValueError("Identifier cannot be empty.")
    s = identifier.strip()
    if is_hex_64(s):
        return s.lower()  # Standardize to lowercase
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def config_path_for_filename(filename: str) -> str:
    """Constructs the full path to a config file, preventing path traversal."""
    # Ensure filename doesn't contain path separators
    if os.path.sep in filename or filename.startswith(".."):
        raise ValueError("Invalid file name.")
    filepath = os.path.join(CONFIG_DIR, filename)
    abs_config_path = os.path.abspath(filepath)
    abs_config_dir = os.path.abspath(CONFIG_DIR)
    if not abs_config_path.startswith(abs_config_dir):
        raise ValueError("Invalid file path (potential path traversal).")
    return filepath

def save_json(path: str, obj: dict):
    """Saves a JSON object to a file with restricted permissions."""
    try:
        txt = json.dumps(obj, indent=2, ensure_ascii=False) + "\n"
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(txt)
            fh.flush()
            try:
                os.fsync(fh.fileno())
            except OSError:
                pass
        os.replace(tmp, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    except (OSError, TypeError, ValueError) as e:
        logging.error(f"Error saving JSON to {path}: {e}")
        raise

def redact_api_keys(obj):
    """Redacts OpenAI API keys in a dictionary or list."""
    if isinstance(obj, dict):
        return {k: "***REDACTED***" if k == "OPENAI_API_KEY" else redact_api_keys(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [redact_api_keys(item) for item in obj]
    return obj

def admin_required(f):
    """Decorator to require admin login for a route."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("is_admin"):
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return decorated_function

def get_license_key(req: request) -> str or None:
    """Extracts the license key from the Authorization header."""
    # Use case-insensitive header lookup
    auth = req.headers.get("Authorization") or req.headers.get("AUTHORIZATION") or ""
    if auth.startswith("Bearer "):
        return auth[7:]
    return None

def get_config(license_key: str) -> dict or None:
    """Retrieves the configuration associated with a license key."""
    if not license_key:
        return None
    sha = compute_hash(license_key)
    config_path = config_path_for_filename(f"{sha}.json")
    if not os.path.exists(config_path):
        return None
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config = json.load(f)
        # Convert keys to uppercase
        return {k.upper(): v for k, v in config.items()}
    except (FileNotFoundError, json.JSONDecodeError, OSError) as e:
        logging.error(f"Error reading config file: {e}")
        return None

def analyze_fields(obj: dict) -> dict:
    """Analyzes the fields in a configuration object for the admin interface."""
    fields = {}
    if not isinstance(obj, dict):
        return fields

    for k, v in obj.items():
        field_type = "string"
        preview = ""

        if isinstance(v, bool):
            field_type = "boolean"
        elif k == "MODEL_SIZE":
            field_type = "model_size"
        elif isinstance(v, (int, float)):
            field_type = "number"
        elif isinstance(v, (dict, list)):
            field_type = "object"
            preview = json.dumps(v, indent=2)

        fields[k] = {"type": field_type, "value": v, "preview": preview}
    return fields

# ---------- Routes ----------
@app.route("/")
def about():
    # It's better practice to have a static file for the homepage.
    # If you have a 'static/index.html' file, serve it. Otherwise show a minimal page.
    static_index = os.path.join(BASE_DIR, "static", "index.html")
    if os.path.exists(static_index):
        return send_from_directory("static", "index.html")
    return "<h1>Translation Live Viewer</h1><p>Visit /admin to manage configs.</p>"

@app.route("/api", methods=["POST"])
def push_data():
    """API endpoint to receive data with a license key."""
    license_key = get_license_key(request)
    if not license_key:
        abort(401, "Missing or invalid Authorization header")

    config = get_config(license_key)
    if not config or "NAME" not in config:
        abort(403, "Invalid license key or configuration")

    try:
        data = request.get_json(force=True)
        name = config["NAME"]

        # Extract text for different languages (fall back to empty strings)
        en_text = data.get("en", "") or ""
        sw_text = data.get("sw", "") or ""
        zh_text = data.get("zh", "") or ""

        logging.info(f"Received data for {name}: {data}")

        # Thread-safe update of the in-memory cache and persist to disk for cross-process consistency
        with RECEIVED_TEXTS_LOCK:
            RECEIVED_TEXTS[name] = {"en": en_text, "sw": sw_text, "zh": zh_text}
            try:
                save_latest_text_file(name, RECEIVED_TEXTS[name])
            except Exception as e:
                logging.error(f"Failed to save latest text to file for {name}: {e}")

        logging.info(f"Updated RECEIVED_TEXTS for '{name}': {RECEIVED_TEXTS[name]}")
        return jsonify({"status": "ok"})
    except (json.JSONDecodeError, TypeError) as e:
        logging.error(f"Error processing JSON data: {e}")
        abort(400, "Invalid JSON data")
    except Exception as e:
        logging.error(f"Unexpected error in /api: {e}")
        abort(500, "Internal server error")

@app.route("/latest/<name>")
def latest_text(name):
    """Endpoint to provide the latest text for a given config name (for live updates)."""
    language = request.args.get("lang", "en")

    # Prefer on-disk file (works across processes). Fall back to in-memory.
    try:
        texts = load_latest_text_file(name)
        if not texts:
            with RECEIVED_TEXTS_LOCK:
                texts = RECEIVED_TEXTS.get(name, {})
    except Exception:
        with RECEIVED_TEXTS_LOCK:
            texts = RECEIVED_TEXTS.get(name, {})

    text_to_send = texts.get(language) if isinstance(texts, dict) else None
    # Ensure we return a string rather than null to prevent frontend flicker
    if text_to_send is None:
        text_to_send = ""
    logging.info(f"Sending '{language}' text for '{name}': {text_to_send!r}")
    return jsonify({"text": text_to_send})

@app.route("/<name>", methods=["GET", "POST"])
def show_config_page(name):
    """Displays a webpage with the latest text received for a given config name."""
    # Load latest from disk first (cross-process) then in-memory cache
    texts = load_latest_text_file(name)
    if not texts:
        with RECEIVED_TEXTS_LOCK:
            texts = RECEIVED_TEXTS.get(name, {})

    if not isinstance(texts, dict):
        texts = {}

    selected_lang = request.form.get("language", "en")
    text = texts.get(selected_lang) or ""

    html = f"""
    <!doctype html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1">
    <title>{name} - Translation Viewer</title>
    <style>
        /* Reset & Base */
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        html, body {{
            height: 100%;
        }}
        /* Prevent page scrolling entirely; keep effects positioned without affecting layout */
        body {{
            background: linear-gradient(135deg, #0f2027, #203a43, #2c5364);
            color: #fff;
            min-height: 100vh;
            height: 100vh;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            font-family: "Segoe UI", Roboto, sans-serif;
            overflow: hidden; /* <-- prevent scrolling */
            padding: env(safe-area-inset-top) env(safe-area-inset-right) env(safe-area-inset-bottom) env(safe-area-inset-left);
            -webkit-font-smoothing: antialiased;
            -moz-osx-font-smoothing: grayscale;
            position: relative;
        }}

        /* Animated background glow (fixed so it doesn't expand layout) */
        body::before {{
            content: "";
            position: fixed;
            inset: -20%;
            width: 140%;
            height: 140%;
            background: radial-gradient(circle at center, rgba(255,255,255,0.05), transparent 70%);
            animation: pulse 8s infinite alternate;
            z-index: 0;
            pointer-events: none;
        }}
        @keyframes pulse {{
            from {{ transform: scale(1) rotate(0deg); opacity: 0.5; }}
            to   {{ transform: scale(1.08) rotate(10deg); opacity: 0.8; }}
        }}

        /* Respect reduced-motion preference */
        @media (prefers-reduced-motion: reduce) {{
            body::before {{ animation: none; }}
            .centered {{ transition: none; animation: none; }}
        }}

        /* Container for main text. Constrain height so it never pushes page taller than viewport. */
        .center-wrapper {{
            position: relative;
            z-index: 1;
            width: 100%;
            max-width: 1100px;
            padding: 1.25rem;
            display: flex;
            align-items: center;
            justify-content: center;
            text-align: center;
            /* ensure this area never exceeds available height */
            max-height: calc(100vh - 92px); /* leave room for fixed controls */
        }}

        .centered {{
            font-weight: 600;
            letter-spacing: 0.25px;
            margin-bottom: 0;
            animation: fadeIn 1.2s ease-in-out;
            z-index: 1;

            /* FONT SCALING -- min 1.25rem, preferred scales with viewport, max 3rem */
            font-size: clamp(1.25rem, 1rem + 4vw, 3rem);

            /* Width constraints so the text body doesn't stretch; lines will wrap instead */
            max-width: min(80ch, 92%);
            width: 100%;

            /* Prevent layout shift when text is empty */
            min-height: 1.6em;
            word-wrap: break-word;
            hyphens: auto;
            line-height: 1.12;
        }}

        /* Fade-in for live text updates */
        #live-text {{
            transition: opacity 0.45s ease, transform 0.45s ease;
            display: inline-block;
        }}
        #live-text.fade {{ opacity: 0; transform: translateY(6px); }}
        #live-text.show {{ opacity: 1; transform: translateY(0); }}

        @keyframes fadeIn {{
            from {{ opacity: 0; transform: translateY(12px); }}
            to   {{ opacity: 1; transform: translateY(0); }}
        }}

        /* Controls are fixed to the bottom center to avoid changing page height */
        .controls {{
            position: fixed;
            bottom: calc(12px + env(safe-area-inset-bottom));
            left: 50%;
            transform: translateX(-50%);
            z-index: 2;
            display: flex;
            align-items: center;
            gap: 0.75rem;
            padding: 0.5rem 0.75rem;
            border-radius: 12px;
            background: linear-gradient(180deg, rgba(255,255,255,0.02), rgba(0,0,0,0.03));
            box-shadow: 0 8px 24px rgba(0,0,0,0.35);
            backdrop-filter: blur(6px);
            margin: 0 12px;
        }}

        label {{ font-size: 1rem; color: #e6eef8; }}
        select {{
            font-size: 1rem;
            padding: 0.6rem 1rem;
            background: #1e293b;
            color: #fff;
            border: none;
            border-radius: 8px;
            outline: none;
            cursor: pointer;
            transition: transform 0.18s ease, box-shadow 0.18s ease;
        }}
        select:hover {{ transform: translateY(-2px); box-shadow: 0 8px 20px rgba(0,0,0,0.3); }}
        select:focus {{ box-shadow: 0 0 0 4px rgba(255,255,255,0.06); }}

        /* Responsive adjustments */
        @media (max-width: 420px) {{
            .controls {{ padding: 0.4rem 0.6rem; gap: 0.5rem; width: auto; }}
            label {{ display: none; }} /* save space on very small screens */
            select {{ width: 140px; }}
            .centered {{ font-size: clamp(1rem, 1rem + 4vw, 2.25rem); }}
        }}
    </style>
    <script>
        // Pause polling when the page is hidden to reduce battery/data use on mobile
        let pollInterval = null;
        function pollLatest() {{
            const lang = document.getElementById('language').value;
            const url = '/latest/{name}?lang=' + encodeURIComponent(lang);
            fetch(url)
                .then(response => response.json())
                .then(data => {{
                    const liveText = document.getElementById('live-text');
                    const newText = data.text || '';

                    if (liveText.textContent !== newText) {{
                        liveText.classList.remove('show');
                        liveText.classList.add('fade');

                        setTimeout(() => {{
                            liveText.textContent = newText;
                            liveText.classList.remove('fade');
                            liveText.classList.add('show');
                        }}, 450);
                    }}
                }})
                .catch(err => {{ console.warn('Error polling latest:', err); }});
        }}

        function startPolling() {{
            if (pollInterval) clearInterval(pollInterval);
            pollLatest();
            pollInterval = setInterval(pollLatest, 2000);
        }}

        function stopPolling() {{
            if (pollInterval) {{ clearInterval(pollInterval); pollInterval = null; }}
        }}

        document.addEventListener('visibilitychange', () => {{
            if (document.hidden) stopPolling(); else startPolling();
        }});

        window.addEventListener('load', () => {{ startPolling(); }});
    </script>
</head>
<body>
    <div class="center-wrapper">
        <div class="centered show" id="live-text" role="status" aria-live="polite">{text}</div>
    </div>

    <form method="post" class="controls" onsubmit="return true;">
        <label for="language">🌐</label>
        <select name="language" id="language" onchange="this.form.submit();">
            <option value="en" {'selected' if selected_lang == 'en' else ''}>English (en)</option>
            <option value="sw" {'selected' if selected_lang == 'sw' else ''}>Swahili (sw)</option>
            <option value="zh" {'selected' if selected_lang == 'zh' else ''}>Chinese (zh)</option>
        </select>
    </form>
</body>
</html>
    """
    return html

# ---------- Admin Routes ----------
@app.route("/admin/", methods=["GET", "POST"])
def admin_login():
    """Admin login page."""
    error = None
    if request.method == "POST":
        password = request.form.get("password", "")
        if password == ADMIN_PASSWORD:
            session.clear()
            session["is_admin"] = True
            return redirect(url_for("admin_dashboard"))
        else:
            error = "Invalid password"
    return render_template_string(TEMPLATE_LOGIN, error=error)

@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    """Admin dashboard."""
    files = [f for f in os.listdir(CONFIG_DIR) if f.endswith(".json")]
    return render_template_string(TEMPLATE_DASH, is_admin=True, files=files)

@app.route("/admin/edit_direct")
@admin_required
def admin_edit_direct():
    """Redirects to the edit page for a config based on license key or SHA."""
    identifier = request.args.get("id", "").strip()
    if not identifier:
        return redirect(url_for("admin_dashboard"))
    try:
        h = compute_hash(identifier)
        fname = f"{h}.json"
        path = config_path_for_filename(fname)
        if not os.path.exists(path):
            save_json(path, {"NAME": "Default Name"})  # Create a default config
        return redirect(url_for("admin_edit", file_name=fname))
    except ValueError as e:
        abort(400, str(e))

@app.route("/admin/edit/<file_name>", methods=["GET", "POST"])
@admin_required
def admin_edit(file_name):
    """Edits a configuration file."""
    try:
        path = config_path_for_filename(file_name)
        obj = {}
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    config = json.load(fh)
                    obj = {k.upper(): v for k, v in config.items()}
            except json.JSONDecodeError:
                obj = {}  # Handle invalid JSON

        if request.method == "POST":
            # Create a new dictionary to store updated values
            updated_obj = obj.copy()

            # Process existing fields
            for k in obj:
                if k == "MODEL_SIZE":
                    val = request.form.get(k)
                    if val in ("tiny", "small"):
                        updated_obj[k] = val
                elif isinstance(obj.get(k), bool):
                    updated_obj[k] = request.form.get(k) == "on"
                elif isinstance(obj.get(k), (int, float)):
                    v = request.form.get(k)
                    try:
                        updated_obj[k] = int(v) if v and '.' not in v else float(v)
                    except (ValueError, TypeError):
                        pass  # Ignore invalid number input
                elif isinstance(obj.get(k), (dict, list)):
                    pass  # Don't allow editing complex types via form
                else:
                    if k in request.form:
                        updated_obj[k] = request.form.get(k)

            # Add new fields
            new_key = request.form.get("new_key")
            new_value = request.form.get("new_value")
            if new_key:
                updated_obj[new_key.upper()] = new_value

            save_json(path, updated_obj)
            return redirect(url_for("admin_edit", file_name=file_name))

        fields = analyze_fields(obj)
        return render_template_string(TEMPLATE_EDIT, file_name=file_name, fields=fields, is_admin=True)

    except ValueError as e:
        abort(400, str(e))
    except OSError:
        abort(500, "Could not read or write file.")

@app.route("/admin/view_raw/<file_name>")
@admin_required
def admin_view_raw(file_name):
    """Displays the raw JSON content of a config file."""
    try:
        path = config_path_for_filename(file_name)
        if not os.path.exists(path):
            abort(404)
        with open(path, "r", encoding="utf-8") as fh:
            raw_text = fh.read()
        return render_template_string(TEMPLATE_RAW, file_name=file_name, raw_text=raw_text)
    except ValueError:
        abort(400, "Invalid file name.")
    except OSError:
        abort(500, "Could not read file.")

@app.route("/admin/save_raw/<file_name>", methods=["POST"])
@admin_required
def admin_save_raw(file_name):
    """Saves raw JSON content to a config file."""
    try:
        raw = request.form.get("raw", "")
        obj = json.loads(raw)  # Validate JSON
        path = config_path_for_filename(file_name)
        save_json(path, obj)
        return redirect(url_for("admin_dashboard"))
    except json.JSONDecodeError:
        abort(400, "Invalid JSON.")
    except ValueError as e:
        abort(400, str(e))
    except OSError:
        abort(500, "Could not write file.")

@app.route("/admin/reveal_key/<file_name>", methods=["GET"])
@admin_required
def admin_reveal_key_view(file_name):
    """Reveals the OpenAI API key from a config file (admin only)."""
    try:
        path = config_path_for_filename(file_name)
        if not os.path.exists(path):
            abort(404)

        with open(path, "r", encoding="utf-8") as fh:
            try:
                config = json.load(fh)
                obj = {k.upper(): v for k,v in config.items()}
            except json.JSONDecodeError:
                obj = {}

        key = obj.get("OPENAI_API_KEY")
        return render_template_string(TEMPLATE_REVEAL, file_name=file_name, key=key)
    except ValueError:
        abort(400, "Invalid file name.")
    except OSError:
        abort(500, "Could not read file.")

@app.route("/admin/save_key/<file_name>", methods=["POST"])
@admin_required
def admin_save_key(file_name):
    """Saves the OpenAI API key to a config file (admin only)."""
    try:
        key = request.form.get("key", "")
        path = config_path_for_filename(file_name)
        obj = {}
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    config = json.load(fh)
                    obj = {k.upper(): v for k, v in config.items()}
            except json.JSONDecodeError:
                obj = {}

        obj["OPENAI_API_KEY"] = key
        save_json(path, obj)
        return redirect(url_for("admin_dashboard"))
    except ValueError:
        abort(400, "Invalid file name.")
    except OSError:
        abort(500, "Could not write file.")

@app.route("/admin/logout")
def admin_logout():
    """Logs out the admin user."""
    session.clear()
    return redirect(url_for("admin_login"))

@app.route("/admin/api/list")
@admin_required
def admin_api_list():
    """API endpoint to list config files (admin only)."""
    try:
        entries = []
        for filename in sorted(os.listdir(CONFIG_DIR)):
            if not filename.endswith(".json"):
                continue
            filepath = config_path_for_filename(filename)
            st = os.stat(filepath)
            entries.append({
                "hash": filename[:-5],
                "name": filename,
                "modified": datetime.fromtimestamp(st.st_mtime).isoformat(),
                "size": st.st_size,
            })
        return jsonify({"ok": True, "files": entries})
    except OSError:
        abort(500, "Could not list files.")

@app.route("/admin/api/delete", methods=["POST"])
@admin_required
def admin_api_delete():
    """API endpoint to delete a config file (admin only)."""
    data = request.get_json() or {}
    filename = data.get("file_name")
    if not filename:
        return jsonify({"ok": False, "error": "file_name required"}), 400

    try:
        path = config_path_for_filename(filename)
        if not os.path.exists(path):
            return jsonify({"ok": False, "error": "not_found"}), 404
        os.remove(path)
        return jsonify({"ok": True, "file": filename})
    except ValueError:
        return jsonify({"ok": False, "error": "Invalid file name"}), 400
    except OSError:
        return jsonify({"ok": False, "error": "Could not delete file"}), 500

@app.route("/admin/download/<file_name>")
@admin_required
def admin_download(file_name):
    """Allows downloading a config file (admin only)."""
    try:
        return send_from_directory(CONFIG_DIR, file_name, as_attachment=True)
    except FileNotFoundError:
        abort(404)
    except ValueError:
        abort(400, "Invalid file name.")

# ---------- Error Handling ----------
@app.errorhandler(400)
def bad_request(error):
    return render_template_string("<h1>400 Bad Request</h1><p>{{ error.description }}</p>", error=error), 400

@app.errorhandler(401)
def unauthorized(error):
    return render_template_string("<h1>401 Unauthorized</h1><p>{{ error.description }}</p>", error=error), 401

@app.errorhandler(403)
def forbidden(error):
    return render_template_string("<h1>403 Forbidden</h1><p>{{ error.description }}</p>", error=error), 403

@app.errorhandler(404)
def not_found(error):
    return render_template_string("<h1>404 Not Found</h1><p>{{ error.description }}</p>", error=error), 404

@app.errorhandler(500)
def internal_server_error(error):
    return render_template_string("<h1>500 Internal Server Error</h1><p>{{ error.description }}</p>", error=error), 500

# ---------- Templates ----------
TEMPLATE_LOGIN = r'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet"><title>Admin Login</title></head><body class="bg-light"><div class="container py-5"><div class="row justify-content-center"><div class="col-md-6"><div class="card shadow-sm"><div class="card-body"><h4 class="card-title">Admin Login</h4><form method="post" action="{{ url_for('admin_login') }}"><div class="mb-3"><input type="password" name="password" class="form-control" placeholder="Admin password" required></div><div class="d-flex gap-2"><button class="btn btn-primary" type="submit">Login</button></div></form>{% if error %}<div class="mt-3 text-danger">{{ error }}</div>{% endif %}</div></div></div></div></div></body></html>'''
TEMPLATE_DASH = r'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet"><title>Dashboard</title></head><body class="bg-light"><div class="container py-4"><div class="d-flex justify-content-between align-items-center mb-3"><h3>Dashboard</h3><div><span class="badge bg-success">Admin</span><a class="btn btn-sm btn-outline-danger ms-2" href="{{ url_for('admin_logout') }}">Logout</a></div></div><div class="row g-3"><div class="col-md-4"><div class="card p-3"><h6>Configs</h6><ul class="list-unstyled">{% for f in files %}<li class="mb-1"><a href="{{ url_for('admin_edit', file_name=f) }}">{{ f }}</a></li>{% else %}<li>No configs found.</li>{% endfor %}</ul><hr><form method="get" action="{{ url_for('admin_edit_direct') }}"><input name="id" class="form-control mb-2" placeholder="license key or sha"><button class="btn btn-primary w-100">Open or Create</button></form></div></div><div class="col-md-8"><div class="card p-3"><h6>Quick actions</h6><p class="text-muted">Use the left panel to open a config. You can view raw JSON and reveal API keys.</p></div></div></div></div></body></html>'''
TEMPLATE_EDIT = r'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet"><title>Edit Config</title></head><body class="bg-light"><div class="container py-4"><a class="btn btn-link mb-3" href="{{ url_for('admin_dashboard') }}">← Back to Dashboard</a><div class="card p-3"><form method="post"><h5>Editing {{ file_name }}</h5><hr>{% for name, info in fields.items() %}<div class="mb-3 row"><label class="col-sm-3 col-form-label">{{ name }}</label><div class="col-sm-9">{% if info.type == 'boolean' %}<div class="form-check form-switch pt-2"><input class="form-check-input" type="checkbox" name="{{ name }}" {% if info.value %}checked{% endif %}></div>{% elif info.type == 'model_size' %}<select name="{{ name }}" class="form-select"><option value="tiny" {% if info.value == 'tiny' %}selected{% endif %}>Speed (tiny)</option><option value="small" {% if info.value == 'small' %}selected{% endif %}>Performance (small)</option></select>{% elif info.type == 'number' %}<input type="number" step="any" name="{{ name }}" value="{{ info.value }}" class="form-control">{% elif info.type == 'object' %}<textarea class="form-control" rows="4" readonly>{{ info.preview }}</textarea><small class="form-text text-muted">Edit complex objects in Raw JSON view.</small>{% else %}<input name="{{ name }}" class="form-control" value="{{ info.value }}">{% endif %}</div></div>{% endfor %}<hr><h6>Add New Field</h6><div class="row g-2"><div class="col-md-5"><input name="new_key" class="form-control" placeholder="New Key (e.g., TIMEOUT)"></div><div class="col-md-7"><input name="new_value" class="form-control" placeholder="New Value (e.g., 30)"></div></div><hr><div class="d-flex gap-2 mt-3"><button class="btn btn-primary" type="submit">Save Changes</button><a class="btn btn-outline-secondary" href="{{ url_for('admin_view_raw', file_name=file_name) }}">View Raw JSON</a><a class="btn btn-outline-warning" href="{{ url_for('admin_reveal_key_view', file_name=file_name) }}">API Key</a></div></form></div></div></body></html>'''
TEMPLATE_RAW = r'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet"><title>Raw JSON</title></head><body class="bg-light"><div class="container py-4"><a class="btn btn-link mb-3" href="{{ url_for('admin_edit', file_name=file_name) }}">← Back to Edit</a><div class="card p-3"><h5>Raw JSON — {{ file_name }}</h5><form method="post" action="{{ url_for('admin_save_raw', file_name=file_name) }}"><textarea name="raw" class="form-control font-monospace" rows="20">{{ raw_text }}</textarea><div class="mt-3"><button class="btn btn-primary">Save Raw JSON</button></div></form></div></div></body></html>'''
TEMPLATE_REVEAL = r'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet"><title>Reveal API Key</title></head><body class="bg-light"><div class="container py-4"><a class="btn btn-link mb-3" href="{{ url_for('admin_edit', file_name=file_name) }}">← Back to Edit</a><div class="card p-3"><h5>OpenAI API Key</h5><form method="post" action="{{ url_for('admin_save_key', file_name=file_name) }}"><div class="mb-3"><label class="form-label">API Key for {{ file_name }}</label><input name="key" value="{{ key or '' }}" class="form-control font-monospace" placeholder="sk-..."></div><div class="mt-3"><button class="btn btn-primary">Save Key</button></div></form>{% if not key %}<div class="mt-3 alert alert-warning">No API key is currently set for this configuration.</div>{% endif %}</div></div></body></html>'''

# ---------- Run ----------
if __name__ == "__main__":
    # For production, spawn with Gunicorn:
    #   gunicorn -w 4 myapp:app
    # But for local testing:
    app.run(debug=False, host="0.0.0.0", port=5000)
