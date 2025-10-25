import os
import json
import time
import base64
import hashlib
from typing import Dict, Any, Optional

from flask import Flask, request, jsonify, make_response
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ----- Settings -----
CONFIG_DIR = os.getenv("CONFIG_DIR", os.path.abspath(os.path.join(os.path.dirname(__file__), "configs")))
TOKEN_BYTES = 12  # AES-GCM nonce
SALT_BYTES = 16
DEFAULT_TTL_SECONDS = int(os.getenv("CONFIG_TTL_SECONDS", "3600"))  # default 1h
MAX_CONFIG_SIZE_BYTES = 128 * 1024  # 128KB guard
ALG = "AESGCM-HKDF-SHA256"
HKDF_INFO = b"cfg-v1"

# Basic in-memory rate-limiting per IP (simple and best-effort)
RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE", "60"))
_rate_bucket: Dict[str, Dict[str, Any]] = {}

app = Flask(__name__)


def _now() -> int:
    return int(time.time())


def _derive_key(license_key: str, salt: bytes) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=HKDF_INFO)
    return hkdf.derive(license_key.encode("utf-8"))


def _aad(exp: int) -> bytes:
    # Must match client's AAD: json.dumps with separators and sort_keys=True
    aad_obj = {"alg": ALG, "exp": exp}
    return json.dumps(aad_obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _hash_key_id(license_key: str) -> str:
    return hashlib.sha256(license_key.encode("utf-8")).hexdigest()


def _get_bearer_token() -> Optional[str]:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    return auth[len("Bearer "):].strip()


def _rate_limit() -> bool:
    # returns True if allowed, False if limited
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()
    now = _now()
    b = _rate_bucket.get(ip)
    if not b or now - b["ts"] >= 60:
        _rate_bucket[ip] = {"ts": now, "count": 1}
        return True
    if b["count"] >= RATE_LIMIT_PER_MINUTE:
        return False
    b["count"] += 1
    return True


def _load_plain_config(path: str) -> Dict[str, Any]:
    st = os.stat(path)
    if st.st_size > MAX_CONFIG_SIZE_BYTES:
        raise ValueError("config too large")
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("config root must be an object")
    return data


@app.after_request
def _security_headers(resp):
    # Basic security headers for API responses
    resp.headers.setdefault("Cache-Control", "no-store")
    resp.headers.setdefault("Pragma", "no-cache")
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Content-Security-Policy", "default-src 'none'")
    return resp


@app.route("/health", methods=["GET"])  # Simple health endpoint
def health():
    return jsonify({"status": "ok"})


@app.route("/v1/env", methods=["POST"])  # Main config endpoint used by client
def v1_env():
    if not _rate_limit():
        return make_response(jsonify({"error": "rate_limited"}), 429)

    token = _get_bearer_token()
    if not token or len(token) != 64:
        return make_response(jsonify({"error": "invalid_or_missing_token"}), 401)

    key_id = _hash_key_id(token)
    cfg_path = os.path.join(CONFIG_DIR, f"{key_id}.json")

    if not os.path.isfile(cfg_path):
        # Hide existence, respond unauthorized
        return make_response(jsonify({"error": "unauthorized"}), 401)

    try:
        env = _load_plain_config(cfg_path)
    except Exception:
        return make_response(jsonify({"error": "server_config_error"}), 500)

    # Ensure only serializable simple JSON is sent
    try:
        plaintext = json.dumps(env, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    except Exception:
        return make_response(jsonify({"error": "invalid_config_json"}), 500)

    exp_ttl = DEFAULT_TTL_SECONDS
    try:
        exp_ttl = max(60, int(os.getenv("CONFIG_TTL_SECONDS", str(DEFAULT_TTL_SECONDS))))
    except Exception:
        pass
    exp = _now() + exp_ttl

    salt = os.urandom(SALT_BYTES)
    key = _derive_key(token, salt)
    nonce = os.urandom(TOKEN_BYTES)

    aad = _aad(exp)
    try:
        ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    except Exception:
        return make_response(jsonify({"error": "encryption_failed"}), 500)

    payload = {
        "alg": ALG,
        "exp": exp,
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ct": base64.b64encode(ct).decode("ascii"),
    }

    return jsonify(payload)


def ensure_dirs():
    os.makedirs(CONFIG_DIR, exist_ok=True)


if __name__ == "__main__":
    ensure_dirs()
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8001"))
    # In production, run behind HTTPS (reverse proxy) and set a stronger WAF/rate limit
    app.run(host=host, port=port)