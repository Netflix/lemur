#!/usr/bin/env bash
# Demo: Certificate body visibility requires break-glass role.
# 1. Login as user/pass and request a certificate -> body is NOT present.
# 2. Grant temporary break-glass to that user (admin-only).
# 3. Request the same certificate again -> body IS present.
#
# Prerequisites:
#   - Apply the break-glass migration (creates temporary_break_glass_grants table):
#       lemur db upgrade
#     or with Alembic directly (from repo root, with LEMUR_CONF set):
#       alembic upgrade head
#   - Restart Lemur so the new API routes and schema changes are loaded.
#
# Usage (with local Lemur running):
#   ./demo_break_glass.sh
#   # or if Lemur is on a different host/port:
#   LEMUR_URL=https://localhost:8447 ./demo_break_glass.sh
set -e

LEMUR_URL="${LEMUR_URL:-https://localhost:8447}"
API="${LEMUR_URL}/api/1"
# Use -k for HTTPS with self-signed cert (local nginx)
CURL_OPTS="-s"
case "${LEMUR_URL}" in https*) CURL_OPTS="-sk" ;; esac

echo "=== Lemur break-glass demo (base: $API) ==="
echo ""

# 1. Login
echo "1. Logging in as user / pass ..."
LOGIN_RESP=$(curl $CURL_OPTS -X POST "${API}/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"user","password":"pass"}')
TOKEN=$(echo "$LOGIN_RESP" | python3 -c "import sys, json; d=json.load(sys.stdin); print(d.get('token',''))" 2>/dev/null || true)
if [ -z "$TOKEN" ]; then
  echo "Login failed. Response: $LOGIN_RESP"
  exit 1
fi
echo "   Token obtained."
echo ""

# 2. Get current user id (for granting break-glass)
USER_ID=$(curl $CURL_OPTS -H "Authorization: Bearer $TOKEN" "${API}/auth/me" | \
  python3 -c "import sys, json; d=json.load(sys.stdin); print(d.get('id',''))" 2>/dev/null || true)
if [ -z "$USER_ID" ]; then
  echo "Could not get /auth/me (user id)."
  exit 1
fi
echo "2. Current user id: $USER_ID"
echo ""

# 3. Get first certificate (list) to get an id
CERT_LIST=$(curl $CURL_OPTS -H "Authorization: Bearer $TOKEN" "${API}/certificates?count=1&page=1")
CERT_ID=$(echo "$CERT_LIST" | python3 -c "
import sys, json
d = json.load(sys.stdin)
items = d.get('items') or []
print(items[0]['id'] if items else '')
" 2>/dev/null || true)

if [ -z "$CERT_ID" ]; then
  echo "No certificates in Lemur. Create one first, then re-run this script."
  exit 1
fi
echo "3. Using certificate id: $CERT_ID"
echo ""

# 4. Request certificate WITHOUT break-glass -> body should be absent
echo "4. GET /certificates/$CERT_ID (without break-glass) ..."
CERT_NO_BG=$(curl $CURL_OPTS -H "Authorization: Bearer $TOKEN" "${API}/certificates/${CERT_ID}")
HAS_BODY_NO_BG=$(echo "$CERT_NO_BG" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print('yes' if d.get('body') else 'no')
" 2>/dev/null || true)
echo "   Response contains 'body' (certificate PEM): $HAS_BODY_NO_BG"
if [ "$HAS_BODY_NO_BG" = "yes" ]; then
  echo "   (Expected: no — without break-glass, body is hidden)"
else
  echo "   (Correct: certificate body is hidden without break-glass)"
fi
echo ""

# 5. Grant temporary break-glass to current user (admin-only)
echo "5. Granting temporary break-glass to user $USER_ID (expires in 1 hour) ..."
GRANT_RESP=$(curl $CURL_OPTS -w "\n%{http_code}" -X POST "${API}/users/${USER_ID}/break-glass" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"expires_in_hours": 1}')
HTTP_BODY=$(echo "$GRANT_RESP" | head -n -1)
HTTP_CODE=$(echo "$GRANT_RESP" | tail -n 1)
if [ "$HTTP_CODE" != "200" ]; then
  echo "   Grant failed (HTTP $HTTP_CODE). Response: $HTTP_BODY"
  echo "   (Ensure the user has admin role so they can grant break-glass.)"
  exit 1
fi
echo "   Break-glass granted."
echo ""

# 6. Request same certificate again WITH break-glass -> body should be present
echo "6. GET /certificates/$CERT_ID (with break-glass) ..."
CERT_WITH_BG=$(curl $CURL_OPTS -H "Authorization: Bearer $TOKEN" "${API}/certificates/${CERT_ID}")
HAS_BODY_WITH_BG=$(echo "$CERT_WITH_BG" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print('yes' if d.get('body') else 'no')
" 2>/dev/null || true)
echo "   Response contains 'body' (certificate PEM): $HAS_BODY_WITH_BG"
if [ "$HAS_BODY_WITH_BG" = "yes" ]; then
  echo "   (Correct: certificate body is visible with break-glass)"
else
  echo "   (Expected: yes — with break-glass, body should be visible)"
fi
echo ""

# 7. Optional: try private key endpoint (also restricted; may 403 without permission)
echo "7. GET /certificates/$CERT_ID/key (private key) ..."
KEY_RESP=$(curl $CURL_OPTS -w "\n%{http_code}" -H "Authorization: Bearer $TOKEN" "${API}/certificates/${CERT_ID}/key")
KEY_BODY=$(echo "$KEY_RESP" | head -n -1)
KEY_CODE=$(echo "$KEY_RESP" | tail -n 1)
if [ "$KEY_CODE" = "200" ]; then
  echo "   Private key returned (user has permission and break-glass)."
elif [ "$KEY_CODE" = "403" ]; then
  echo "   HTTP 403 — not authorized to view this key (certificate owner/role check)."
else
  echo "   HTTP $KEY_CODE — $KEY_BODY"
fi
echo ""

# 8. Revoke break-glass for the user
echo "8. Revoking temporary break-glass for user $USER_ID ..."
REVOKE_CODE=$(curl $CURL_OPTS -o /dev/null -w "%{http_code}" -X DELETE \
  -H "Authorization: Bearer $TOKEN" "${API}/users/${USER_ID}/break-glass")
if [ "$REVOKE_CODE" = "204" ]; then
  echo "   Break-glass revoked."
else
  echo "   HTTP $REVOKE_CODE (expected 204)."
fi
echo ""

echo "=== Demo complete ==="
echo "Summary: Certificate 'body' is hidden for users without the break-glass role;"
echo "after an admin grants temporary break-glass, the same user can see the body."
echo "Break-glass was revoked at the end of this run."
