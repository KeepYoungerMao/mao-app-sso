#!/bin/bash
# 对运行中的应用执行完整 OAuth 2.1 授权码 + PKCE 流程（curl）
set -u
BASE=http://localhost:8080
CURL="curl -s --noproxy '*'"
CLIENT_ID=mao-web-client
CLIENT_SECRET=smoke-client-secret
REDIRECT_URI=http://localhost:9000/login/oauth2/code/mao-web-client
USERNAME=admin
PASSWORD=smoke-admin-pass
JAR=/tmp/sso-smoke-jar.txt

CODE_VERIFIER=$(openssl rand -base64 48 | tr '+/' '-_' | tr -d '=\n')
CODE_CHALLENGE=$(printf %s "$CODE_VERIFIER" | openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '=\n')
STATE="state-$RANDOM"

echo "== 1. 未登录访问授权端点（期望 302 -> /login）"
$CURL -c $JAR -o /dev/null -w "  status=%{http_code} location=%{redirect_url}\n" \
  -H "Accept: text/html" "$BASE/oauth2/authorize?response_type=code&client_id=$CLIENT_ID&scope=openid%20profile%20email&redirect_uri=$REDIRECT_URI&state=$STATE&code_challenge=$CODE_CHALLENGE&code_challenge_method=S256"

echo "== 2. 登录（期望 302 -> 授权端点）"
CSRF=$($CURL -c $JAR -b $JAR -H "Accept: text/html" "$BASE/login" | grep -oP 'name="_csrf" value="\K[^"]+' | head -1)
$CURL -c $JAR -b $JAR -o /dev/null -w "  status=%{http_code} location=%{redirect_url}\n" \
  -X POST -H "Accept: text/html" "$BASE/login" -d "username=$USERNAME&password=$PASSWORD&_csrf=$CSRF"

echo "== 3. 再次授权（期望 302 -> /oauth2/consent）"
LOC3=$($CURL -c $JAR -b $JAR -o /dev/null -w "%{redirect_url}" \
  -H "Accept: text/html" "$BASE/oauth2/authorize?response_type=code&client_id=$CLIENT_ID&scope=openid%20profile%20email&redirect_uri=$REDIRECT_URI&state=$STATE&code_challenge=$CODE_CHALLENGE&code_challenge_method=S256")
echo "  location=$LOC3"

echo "== 4. 授权确认页（期望 200）"
CONSENT_STATE=$(printf %s "$LOC3" | grep -oP 'state=\K[^&]+')
$CURL -c $JAR -b $JAR -o /dev/null -w "  status=%{http_code}\n" \
  -H "Accept: text/html" "$BASE/oauth2/consent?client_id=$CLIENT_ID&scope=openid%20profile%20email&state=$CONSENT_STATE"

echo "== 5. 提交授权确认（期望 302 -> redirect_uri?code=...）"
CSRF2=$($CURL -c $JAR -b $JAR -H "Accept: text/html" "$BASE/oauth2/consent?client_id=$CLIENT_ID&scope=openid%20profile%20email&state=$CONSENT_STATE" | grep -oP 'name="_csrf" value="\K[^"]+' | head -1)
LOC5=$($CURL -c $JAR -b $JAR -o /dev/null -w "%{redirect_url}" \
  -X POST "$BASE/oauth2/authorize" \
  -d "client_id=$CLIENT_ID&state=$CONSENT_STATE&scope=openid&scope=profile&scope=email&_csrf=$CSRF2")
echo "  location=$LOC5"
CODE=$(printf %s "$LOC5" | grep -oP 'code=\K[^&]+')

echo "== 6. 换取 Token（期望 200 + access/refresh/id token）"
TOKEN_JSON=$($CURL -X POST "$BASE/oauth2/token" -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d "grant_type=authorization_code&code=$CODE&redirect_uri=$REDIRECT_URI&code_verifier=$CODE_VERIFIER")
echo "  $(printf %s "$TOKEN_JSON" | head -c 160)..."
ACCESS_TOKEN=$(printf %s "$TOKEN_JSON" | grep -oP '"access_token":"\K[^"]+')
REFRESH_TOKEN=$(printf %s "$TOKEN_JSON" | grep -oP '"refresh_token":"\K[^"]+')

echo "== 7. UserInfo（期望 200 + sub/name/email）"
$CURL -w "\n  status=%{http_code}\n" "$BASE/userinfo" -H "Authorization: Bearer $ACCESS_TOKEN"

echo "== 8. Refresh Token 轮换（期望 200 + 新 access_token）"
$CURL -o /dev/null -w "  status=%{http_code}\n" -X POST "$BASE/oauth2/token" -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d "grant_type=refresh_token&refresh_token=$REFRESH_TOKEN"

echo "== 9. 旧 Refresh Token 复用（期望 400 invalid_grant）"
$CURL -w "\n  status=%{http_code}\n" -X POST "$BASE/oauth2/token" -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d "grant_type=refresh_token&refresh_token=$REFRESH_TOKEN"

echo "== 10. 错误 code_verifier 换 Token（期望 400 invalid_grant）"
CODE2=$($CURL -c $JAR -b $JAR -o /dev/null -w "%{redirect_url}" \
  -H "Accept: text/html" "$BASE/oauth2/authorize?response_type=code&client_id=$CLIENT_ID&scope=openid&redirect_uri=$REDIRECT_URI&state=st2&code_challenge=$CODE_CHALLENGE&code_challenge_method=S256" | grep -oP 'code=\K[^&]+')
$CURL -w "\n  status=%{http_code}\n" -X POST "$BASE/oauth2/token" -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d "grant_type=authorization_code&code=$CODE2&redirect_uri=$REDIRECT_URI&code_verifier=wrong-verifier"
