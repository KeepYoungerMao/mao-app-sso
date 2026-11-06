import os
"""端到端模拟 WorkBuddy 的 MCP 授权流程：DCR -> 授权码(PKCE) -> Token。

注：DCR 端现在按 redirect_uri 查表返回预录入的固定 client_id，
所有客户端需先在管理后台 /admin/clients 预先录入。"""
import base64
import hashlib
import http.cookiejar
import json
import re
import urllib.parse
import urllib.request

BASE = "http://127.0.0.1:8080"
REDIRECT = "workbuddy://workbuddy/mcp/custom-mcp%3Ascnet-ocr-recognition/oauth/callback"
RESOURCE = "http://223.113.240.17:30549/mcp"
SCOPES = "openid profile email"  # 需与 sso.dcr.allowed-scopes 白名单一致

jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
opener.addheaders = [("User-Agent", "curl-like"), ("Accept", "text/html")]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


opener_nr = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(jar), NoRedirect
)
opener_nr.addheaders = [("User-Agent", "curl-like"), ("Accept", "text/html")]


def get(url, follow=True):
    o = opener if follow else opener_nr
    try:
        with o.open(url) as r:
            return r.status, r.read().decode("utf-8", "ignore"), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "ignore"), dict(e.headers)


def post(url, data, follow=False):
    o = opener if follow else opener_nr
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with o.open(req) as r:
            return r.status, r.read().decode("utf-8", "ignore"), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "ignore"), dict(e.headers)


def csrf(html):
    m = re.search(r'name="_csrf"\s+value="([^"]+)"', html)
    return m.group(1) if m else None


# ---------- 1. DCR ----------
# 设置 E2E_CLIENT_ID 可跳过注册、直接用已存在的客户端（用于复现预注册客户端的真实行为）
client_id = os.environ.get("E2E_CLIENT_ID")
if client_id:
    print("[1] 使用已有客户端（跳过 DCR） client_id =", client_id)
else:
    dcr_body = json.dumps({
        "client_name": "WorkBuddy MCP (e2e)",
        "redirect_uris": [REDIRECT],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
        "scope": SCOPES,
    }).encode()
    req = urllib.request.Request(BASE + "/oauth2/register", data=dcr_body, method="POST")
    req.add_header("Content-Type", "application/json")
    try:
        with opener.open(req) as r:
            reg = json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        print("[1] DCR 失败 ->", e.code, e.read().decode("utf-8", "ignore")[:300])
        raise
    client_id = reg["client_id"]
    print("[1] DCR OK  client_id =", client_id)
    print("    token_endpoint_auth_method =", reg.get("token_endpoint_auth_method"))

SCOPES = os.environ.get("E2E_SCOPES", SCOPES)

# ---------- 2. 授权请求（带 resource） ----------
verifier = "e2everifier-0123456789-abcdefghijklmnopqrstu"
challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
auth_url = BASE + "/oauth2/authorize?" + urllib.parse.urlencode({
    "response_type": "code", "client_id": client_id,
    "code_challenge": challenge, "code_challenge_method": "S256",
    "redirect_uri": REDIRECT, "state": "st-e2e", "scope": SCOPES,
    "resource": RESOURCE,
})
st, _, hd = get(auth_url, follow=False)
print("[2] authorize (未登录) ->", st, hd.get("Location"))

# ---------- 3. 登录 ----------
st, login_html, _ = get(BASE + "/login")
st, _, hd = post(BASE + "/login", {
    "username": "admin", "password": "admin", "_csrf": csrf(login_html),
}, follow=False)
print("[3] login ->", st, hd.get("Location"))

# ---------- 4. 回到授权端点 -> consent ----------
st, _, hd = get(auth_url, follow=False)
loc = hd.get("Location")
print("[4] authorize (已登录) ->", st, loc)

# ---------- 5. consent 页 ----------
if loc and "/oauth2/consent" in loc:
    state = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query).get("state", [""])[0]
    st, consent_html, _ = get(loc)
    token = csrf(consent_html)
    print("[5] consent 页 CSRF =", bool(token))
    # 提交同意：与 consent.html 表单一致，全部参数放 body
    form = [("_csrf", token), ("client_id", client_id), ("state", state)]
    for s in SCOPES.split(" "):
        form.append(("scope", s))
    st, body, hd = post(BASE + "/oauth2/authorize", form, follow=False)
    loc = hd.get("Location")
    # 自定义协议（workbuddy:// 等）不返回 302，而是渲染中间页（CustomSchemeRedirectFilter），
    # 真实浏览器中由用户点击页内链接完成跳转；脚本直接从 HTML 解析该链接继续流程
    if not loc and st == 200:
        m = re.search(r'href="([a-zA-Z][a-zA-Z0-9+.\-]*://[^"]+)"', body)
        if m:
            loc = m.group(1)
            print("[6] consent 提交 -> 200（中间页）链接已提取")
        else:
            print("[6] consent 提交 -> 200 但未找到跳转链接，body:", body[:200])
    else:
        print("[6] consent 提交 ->", st, loc)
    if st >= 400:
        print("    body:", body[:300])
else:
    print("[5] 未进入 consent 页，直接 location:", loc)

# ---------- 7. 换 token ----------
code = urllib.parse.parse_qs(urllib.parse.urlparse(loc or "").query).get("code", [None])[0]
print("[7] code =", code)
refresh_token = None
if code:
    st, body, _ = post(BASE + "/oauth2/token", {
        "grant_type": "authorization_code", "code": code,
        "redirect_uri": REDIRECT, "client_id": client_id,
        "code_verifier": verifier,
    }, follow=True)
    print("[8] token ->", st)
    try:
        tok = json.loads(body)
        refresh_token = tok.get("refresh_token")
        print("    access_token 前 40 位:", str(tok.get("access_token"))[:40])
        print("    refresh_token 存在:", bool(refresh_token))
        print("    scope:", tok.get("scope"))
        seg = tok.get("access_token", "").split(".")
        if len(seg) == 3:
            pad = "=" * (-len(seg[1]) % 4)
            print("    AT payload:", json.loads(base64.urlsafe_b64decode(seg[1] + pad)))
    except Exception as e:
        print("    body:", body[:500], e)

# ---------- 9. 公共客户端 refresh 静默续期 ----------
if refresh_token:
    st, body, _ = post(BASE + "/oauth2/token", {
        "grant_type": "refresh_token", "refresh_token": refresh_token,
        "client_id": client_id,
    }, follow=True)
    print("[9] refresh_token 续期 ->", st)
    try:
        tok2 = json.loads(body)
        print("    新 access_token 前 40 位:", str(tok2.get("access_token"))[:40])
        print("    新 refresh_token 存在:", bool(tok2.get("refresh_token")))
    except Exception as e:
        print("    body:", body[:500], e)

