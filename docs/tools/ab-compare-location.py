"""A/B 对比实验：授权页 POST 提交 vs 直接 GET 授权，两条路径的 302 Location 是否一致。

背景：WorkBuddy 走 MCP OAuth 时，点"同意授权"（原生表单 POST）后浏览器不跳转 workbuddy://，
而重连时浏览器直接打开授权 URL（GET）却能跳转。本脚本在服务端复现两条路径并对比原始响应头。
"""
import base64
import hashlib
import http.cookiejar
import json
import re
import urllib.error
import urllib.parse
import urllib.request

BASE = "http://127.0.0.1:8080"
REDIRECT = "workbuddy://workbuddy/mcp/custom-mcp%3Ascnet-ocr-recognition/oauth/callback"
SCOPES = "openid profile email"

JAR = http.cookiejar.CookieJar()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(JAR))
opener_nr = urllib.request.build_opener(NoRedirect, urllib.request.HTTPCookieProcessor(JAR))


def csrf(html):
    m = re.search(r'name="_csrf"\s+value="([^"]+)"', html)
    return m.group(1) if m else None


def nr(url, data=None):
    """不跟随重定向的请求，返回 (status, headers, body)"""
    r = urllib.request.Request(url, data=data)
    r.add_header("Accept", "text/html")
    try:
        resp = opener_nr.open(r)
        return resp.status, dict(resp.headers), resp.read().decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode("utf-8", "ignore")


# ---------- 1. DCR 注册 ----------
dcr_body = json.dumps({
    "client_name": "A/B test",
    "redirect_uris": [REDIRECT],
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "token_endpoint_auth_method": "none",
    "scope": SCOPES,
}).encode()
r = urllib.request.Request(BASE + "/oauth2/register", data=dcr_body, method="POST")
r.add_header("Content-Type", "application/json")
reg = json.loads(opener.open(r).read().decode())
client_id = reg["client_id"]
print("[1] client_id =", client_id)

# ---------- 2. 登录 ----------
login_html = opener.open(BASE + "/login").read().decode()
form = urllib.parse.urlencode({"username": "admin", "password": "admin", "_csrf": csrf(login_html)}).encode()
st, hd, _ = nr(BASE + "/login", form)
print("[2] login ->", st, "(302=成功)")

verifier = "abtest-verifier-0123456789-abcdefghijklmn"
challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
auth_qs = urllib.parse.urlencode({
    "response_type": "code", "client_id": client_id,
    "code_challenge": challenge, "code_challenge_method": "S256",
    "redirect_uri": REDIRECT, "state": "st-ab", "scope": SCOPES,
    "resource": "http://223.113.240.17:30549/mcp",
})
auth_url = BASE + "/oauth2/authorize?" + auth_qs

# ---------- 路径 A：授权页表单 POST 提交 ----------
st, hd, body = nr(auth_url)
loc = hd.get("Location")
print("[A0] GET authorize（未同意）->", st, loc)
if loc and "/oauth2/consent" in loc:
    consent_html = opener.open(loc).read().decode()
    # 授权页表单的 state 来自授权页 URL 的查询参数（SAS 生成的关联 ID），不是原始请求的 state
    consent_state = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query).get("state", [None])[0]
    form = [("_csrf", csrf(consent_html)), ("client_id", client_id), ("state", consent_state)]
    for s in SCOPES.split(" "):
        form.append(("scope", s))
    st, hd, body = nr(BASE + "/oauth2/authorize", data=urllib.parse.urlencode(form).encode())
    loc_a = hd.get("Location")
    print("[A] POST 同意授权 ->", st)
    print("    Location =", repr(loc_a))
else:
    print("    body 前 120 字:", body[:120].replace("\n", " "))
    raise SystemExit("未进入授权页，A/B 中止")

# ---------- 路径 B：已同意，直接 GET ----------
st, hd, body = nr(auth_url)
loc_b = hd.get("Location")
print("[B] GET authorize（已同意）->", st)
print("    Location =", repr(loc_b))

print()
print("=== 结论 ===")
print("两条路径 Location 完全一致:", loc_a == loc_b)
if loc_a != loc_b:
    print("A(唯一不同点在此):", loc_a)
    print("B           :", loc_b)
