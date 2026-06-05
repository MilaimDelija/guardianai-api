"""
Vigil API Key Registration System.

Handles:
- API key generation
- Email delivery via Resend
- Key storage in Neon/PostgreSQL
- Per-request authentication and rate limiting
"""

from __future__ import annotations

import hashlib
import http.client
import json
import logging
import os
import secrets
import ssl
import time
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("vigil.register")


# ---------------------------------------------------------------------------
# DATABASE
# ---------------------------------------------------------------------------

def _get_conn():
    import psycopg2
    return psycopg2.connect(os.environ["DATABASE_URL"], connect_timeout=10)


def setup_database() -> None:
    """Create vigil_api_keys table if not exists."""
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS vigil_api_keys (
            id SERIAL PRIMARY KEY,
            key VARCHAR(64) UNIQUE NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            name VARCHAR(255),
            plan VARCHAR(20) DEFAULT 'free',
            requests_used INTEGER DEFAULT 0,
            requests_limit INTEGER DEFAULT 1000,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            last_used_at TIMESTAMPTZ,
            is_active BOOLEAN DEFAULT TRUE
        );
        CREATE INDEX IF NOT EXISTS idx_vigil_keys_key ON vigil_api_keys(key);
        CREATE INDEX IF NOT EXISTS idx_vigil_keys_email ON vigil_api_keys(email);
    """)
    conn.commit()
    cur.close()
    conn.close()
    logger.info("Database ready")


def create_api_key(email: str, name: str) -> str:
    """Generate and store a new API key. Returns the key."""
    key = "vgl-" + secrets.token_urlsafe(32)
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO vigil_api_keys (key, email, name) VALUES (%s, %s, %s)",
        (key, email.lower().strip(), name.strip())
    )
    conn.commit()
    cur.close()
    conn.close()
    return key


def get_key_record(key: str) -> dict[str, Any] | None:
    """Look up a key record. Returns None if not found or inactive."""
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute(
        "SELECT key, email, name, plan, requests_used, requests_limit, is_active FROM vigil_api_keys WHERE key = %s",
        (key,)
    )
    row = cur.fetchone()
    cur.close()
    conn.close()
    if not row:
        return None
    return {
        "key": row[0], "email": row[1], "name": row[2],
        "plan": row[3], "requests_used": row[4],
        "requests_limit": row[5], "is_active": row[6],
    }


def increment_usage(key: str) -> None:
    """Increment request counter and update last_used_at."""
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute(
        "UPDATE vigil_api_keys SET requests_used = requests_used + 1, last_used_at = NOW() WHERE key = %s",
        (key,)
    )
    conn.commit()
    cur.close()
    conn.close()


def email_exists(email: str) -> bool:
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM vigil_api_keys WHERE email = %s", (email.lower().strip(),))
    exists = cur.fetchone() is not None
    cur.close()
    conn.close()
    return exists


# ---------------------------------------------------------------------------
# EMAIL — RESEND
# ---------------------------------------------------------------------------

def send_api_key_email(email: str, name: str, api_key: str) -> bool:
    """Send API key to user via Resend."""
    resend_key = os.environ.get("RESEND_API_KEY", "")
    if not resend_key:
        logger.warning("RESEND_API_KEY not set — skipping email")
        return False

    html = f"""
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  body {{ font-family: -apple-system, sans-serif; background: #020408; color: #e8edf5; margin: 0; padding: 0; }}
  .container {{ max-width: 560px; margin: 40px auto; padding: 40px; background: #080d14; border: 1px solid #1a2540; border-radius: 12px; }}
  .logo {{ display: flex; align-items: center; gap: 10px; margin-bottom: 32px; }}
  .logo-mark {{ width: 32px; height: 32px; background: #00d4ff; border-radius: 6px; display: flex; align-items: center; justify-content: center; font-weight: 800; color: #020408; font-size: 16px; }}
  h1 {{ font-size: 22px; font-weight: 700; margin: 0 0 12px; letter-spacing: -0.02em; }}
  p {{ color: #6b7fa3; font-size: 14px; line-height: 1.6; margin: 0 0 24px; }}
  .key-box {{ background: #0d1520; border: 1px solid #1e3a5f; border-radius: 8px; padding: 16px 20px; margin: 24px 0; }}
  .key-label {{ font-size: 11px; color: #3d4f6e; font-family: monospace; letter-spacing: 0.1em; margin-bottom: 8px; }}
  .key-value {{ font-family: monospace; font-size: 14px; color: #00d4ff; word-break: break-all; }}
  .info {{ background: #0d1520; border-radius: 8px; padding: 16px 20px; margin: 24px 0; }}
  .info-row {{ display: flex; justify-content: space-between; padding: 6px 0; border-bottom: 1px solid #1a2540; font-size: 13px; }}
  .info-row:last-child {{ border-bottom: none; }}
  .info-label {{ color: #3d4f6e; font-family: monospace; font-size: 11px; }}
  .info-value {{ color: #e8edf5; }}
  .footer {{ margin-top: 32px; padding-top: 24px; border-top: 1px solid #1a2540; font-size: 12px; color: #3d4f6e; }}
  a {{ color: #00d4ff; text-decoration: none; }}
</style>
</head>
<body>
<div class="container">
  <div class="logo">
    <div class="logo-mark">V</div>
    <span style="font-weight: 700; font-size: 18px;">Vigil</span>
    <span style="font-size: 11px; color: #3d4f6e; font-family: monospace; margin-left: 4px;">by Neuronium Engineers</span>
  </div>

  <h1>Your API Key is ready, {name.split()[0]}</h1>
  <p>Welcome to Vigil — the security layer built for AI. Your free tier API key is below.</p>

  <div class="key-box">
    <div class="key-label">API KEY</div>
    <div class="key-value">{api_key}</div>
  </div>

  <div class="info">
    <div class="info-row">
      <span class="info-label">PLAN</span>
      <span class="info-value">Free</span>
    </div>
    <div class="info-row">
      <span class="info-label">REQUESTS / MONTH</span>
      <span class="info-value">1,000</span>
    </div>
    <div class="info-row">
      <span class="info-label">LAYER 1 — PATTERN</span>
      <span class="info-value">✓ Active</span>
    </div>
    <div class="info-row">
      <span class="info-label">LAYER 2 — SEMANTIC</span>
      <span class="info-value">✓ Active</span>
    </div>
    <div class="info-row">
      <span class="info-label">BASE URL</span>
      <span class="info-value">https://vigil-dxwx.onrender.com</span>
    </div>
  </div>

  <p>Use your key in every request:</p>
  <div class="key-box">
    <div class="key-label">EXAMPLE REQUEST</div>
    <div class="key-value" style="color: #6b7fa3;">curl -X POST https://vigil-dxwx.onrender.com/v1/scan/input \\<br>
&nbsp;&nbsp;-H "Authorization: Bearer {api_key}" \\<br>
&nbsp;&nbsp;-H "Content-Type: application/json" \\<br>
&nbsp;&nbsp;-d '{{"text": "your input here", "use_semantic": true}}'</div>
  </div>

  <div class="footer">
    <p>Keep your API key secure. Never share it publicly.</p>
    <p style="margin-top: 8px;">
      <a href="https://vigil-web-tau.vercel.app">Documentation</a> ·
      <a href="https://github.com/MilaimDelija/vigil">GitHub</a> ·
      security@neuronium.io
    </p>
    <p style="margin-top: 8px;">Neuronium Engineers · Frankfurt am Main</p>
  </div>
</div>
</body>
</html>
"""

    body = json.dumps({
        "from": "Vigil <onboarding@resend.dev>",
        "to": [email],
        "subject": "Your Vigil API Key",
        "html": html,
    }).encode("utf-8")

    ctx = ssl.create_default_context()
    conn = http.client.HTTPSConnection("api.resend.com", context=ctx, timeout=15)
    conn.request("POST", "/emails", body=body, headers={
        "Content-Type": "application/json",
        "Authorization": f"Bearer {resend_key}",
    })
    resp = conn.getresponse()
    raw = resp.read()

    if resp.status in (200, 201):
        logger.info(f"API key email sent to {email}")
        return True
    else:
        logger.error(f"Resend error {resp.status}: {raw.decode()[:200]}")
        return False


# ---------------------------------------------------------------------------
# AUTH MIDDLEWARE HELPER
# ---------------------------------------------------------------------------

def verify_api_key(key: str) -> tuple[bool, str, dict[str, Any] | None]:
    """
    Verify an API key for request authentication.

    Returns: (is_valid, error_message, record)
    """
    if not key or not key.startswith("vgl-"):
        return False, "Invalid API key format", None

    record = get_key_record(key)
    if not record:
        return False, "API key not found", None
    if not record["is_active"]:
        return False, "API key is disabled", None
    if record["requests_used"] >= record["requests_limit"]:
        return False, f"Monthly limit reached ({record['requests_limit']} requests). Upgrade to Pro for unlimited access.", None

    return True, "", record
