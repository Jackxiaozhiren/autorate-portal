"""Machine-agent reader walkthrough against a running portal.

This is a stand-in for a human P1/P2 reader, never a replacement. It drives the
same HTTP surface a browser SPA would, records each observation as JSON, and
refuses to claim the reader gate. Usage:

    AUTHORATE_TOKEN=... python walkthrough_probe.py http://127.0.0.1:8111

The two tokens below are the walkthrough fixtures from tokens.txt; override with
the env vars. No credential is baked into this file.
"""
from __future__ import annotations

import http.cookiejar
import json
import os
import sys
import urllib.error
import urllib.request

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://127.0.0.1:8111"
TOKEN_ADA = os.environ.get("WALK_TOKEN_ADA", "")
TOKEN_LIN = os.environ.get("WALK_TOKEN_LIN", "")
if not TOKEN_ADA or not TOKEN_LIN:
    print("set WALK_TOKEN_ADA and WALK_TOKEN_LIN", file=sys.stderr)
    sys.exit(2)

jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))


def call(method, path, body=None, csrf=None, token=None):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"}
    if csrf:
        headers["x-csrf-token"] = csrf
    if token:
        headers["x-api-token"] = token
    req = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    try:
        with opener.open(req) as r:
            raw = r.read().decode("utf-8", "replace")
            return r.status, raw
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def js(status, raw):
    try:
        return status, json.loads(raw)
    except Exception:
        return status, raw


out = {"base": BASE, "observations": []}


def record(label, status, value):
    out["observations"].append({"step": label, "http": status, "value": value})
    print(f"[{label}] http={status}")


# 1. fail-closed before identity exists
s, raw = js(*call("GET", "/api/v1/certificates"))
record("unauthenticated_certificates", s, raw if s != 200 else "[unexpected 200]")

# 2. token -> session (cookie carries csrf, not the token)
s, body = js(*call("POST", "/api/v1/session", {"token": TOKEN_ADA}))
csrf = body.get("csrf") if isinstance(body, dict) else None
record("session_issued", s, {k: body.get(k) for k in ("actor", "role", "project_id")}
       if isinstance(body, dict) else body)
cookies = {c.name: {"httponly": bool(c.has_nonstandard_attr("HttpOnly") or
                                     "HttpOnly" in str(c).split()),
                    "value_prefix": c.value[:12]} for c in jar}
out["cookies_after_login"] = cookies

# 3. cookie write without csrf is refused
s, raw = js(*call("POST", "/api/v1/claims/check",
                  {"share": "0.66", "field": "confidence", "unit": "case",
                   "population": "resolutions"}, csrf=None))
record("cookie_write_without_csrf", s, raw)

# 4. first-screen claim question, three states via three fields
for tag, field in (("field_not_measured", "confidence"),
                   ("field_autorate", "autorate"),
                   ("field_empty", "")):
    s, body = js(*call("POST", "/api/v1/claims/check?locale=en",
                       {"share": "0.66", "field": field, "unit": "case",
                        "population": "resolutions"}, csrf=csrf))
    v = {k: body.get(k) for k in ("verdict", "reason", "locale")} if isinstance(body, dict) else body
    record(tag, s, v)

# 5. same question in Chinese
s, body = js(*call("POST", "/api/v1/claims/check?locale=zh-Hans",
                   {"share": "0.66", "field": "confidence", "unit": "case",
                    "population": "resolutions"}, csrf=csrf))
v = {k: body.get(k) for k in ("verdict", "reason", "locale")} if isinstance(body, dict) else body
record("claim_zh", s, v)

# 6. certificate list readable with the session
s, body = js(*call("GET", "/api/v1/certificates"))
record("certificates_via_session", s,
       {"count": len(body) if isinstance(body, list) else None,
        "first": body[0] if isinstance(body, list) and body else None})

# 7. CSRF readable by the page (double submit), i18n catalog, A4 print block
s, raw = call("GET", "/")
out["page"] = {
    "http": s,
    "has_a4_print": "@page { size: A4" in raw or "@page{size: A4" in raw,
    "claim_before_table": raw.find("Check a claim") < raw.find('id="certificates"'),
    "claim_intro_cannot_be_failure": "result, not a failure" in raw,
}
s, body = js(*call("GET", "/api/v1/i18n/zh-Hans"))
out["i18n_zh"] = {k: body.get(k) for k in
                  ("text.claim_intro", "label.check_claim", "state.refusal")} if isinstance(body, dict) else body

# 8. sign out clears cookies; subsequent session read is 401
s, body = js(*call("DELETE", "/api/v1/session", csrf=csrf))
record("session_revoked", s, body)
s, raw = js(*call("GET", "/api/v1/certificates"))
record("after_signout_certificates", s, raw if s != 200 else "[unexpected 200]")

# 9. token-authenticated write does not need csrf (V2-D1 tradeoff)
jar.clear()
s, body = js(*call("POST", "/api/v1/claims/check?locale=en",
                   {"share": "0.66", "field": "confidence", "unit": "case",
                    "population": "resolutions"}, token=TOKEN_LIN))
record("token_write_no_csrf_viewer", s,
       {k: body.get(k) for k in ("verdict", "reason")} if isinstance(body, dict) else body)

print(json.dumps(out, ensure_ascii=False, indent=2))
with open(os.environ.get("WALK_OUT", "/tmp/v2-walkthrough/http/probe.json"), "w") as f:
    json.dump(out, f, ensure_ascii=False, indent=2)
