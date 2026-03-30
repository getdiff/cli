#!/usr/bin/env bash
# Integration tests for the Agent Capability Gateway (Rust)
# Starts proxy + mock API, runs all test scenarios, reports results.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BINARY="${ROOT_DIR}/target/release/getdiff"
PROXY_PORT=8081
MOCKAPI_PORT=9999
PROXY_URL="http://localhost:${PROXY_PORT}"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

PASS=0
FAIL=0
TOTAL=0

# Cleanup
PROXY_PID=""
MOCKAPI_PID=""

cleanup() {
    [ -n "$PROXY_PID" ] && kill "$PROXY_PID" 2>/dev/null || true
    [ -n "$MOCKAPI_PID" ] && kill "$MOCKAPI_PID" 2>/dev/null || true
    wait 2>/dev/null || true
}
trap cleanup EXIT

# Test helpers
assert_status() {
    local desc="$1"
    local expected="$2"
    local actual="$3"
    TOTAL=$((TOTAL + 1))
    if [ "$actual" -eq "$expected" ]; then
        echo -e "  ${GREEN}PASS${NC} $desc (HTTP $actual)"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}FAIL${NC} $desc (expected HTTP $expected, got HTTP $actual)"
        FAIL=$((FAIL + 1))
    fi
}

assert_contains() {
    local desc="$1"
    local expected="$2"
    local actual="$3"
    TOTAL=$((TOTAL + 1))
    if echo "$actual" | grep -qi "$expected"; then
        echo -e "  ${GREEN}PASS${NC} $desc"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}FAIL${NC} $desc"
        echo "    expected to contain: $expected"
        echo "    actual: $(echo "$actual" | head -c 200)"
        FAIL=$((FAIL + 1))
    fi
}

assert_not_contains() {
    local desc="$1"
    local unexpected="$2"
    local actual="$3"
    TOTAL=$((TOTAL + 1))
    if echo "$actual" | grep -q "$unexpected"; then
        echo -e "  ${RED}FAIL${NC} $desc"
        echo "    should NOT contain: $unexpected"
        FAIL=$((FAIL + 1))
    else
        echo -e "  ${GREEN}PASS${NC} $desc"
        PASS=$((PASS + 1))
    fi
}

# ============================================================
# Build & Start
# ============================================================
echo "============================================"
echo "  Agent Capability Gateway - Integration Tests"
echo "============================================"
echo ""

echo "Building release binary..."
(cd "$ROOT_DIR" && cargo build --release) 2>&1 | tail -1

echo "Starting mock API server..."
$BINARY mock-api --port "$MOCKAPI_PORT" > /dev/null 2>&1 &
MOCKAPI_PID=$!
sleep 0.5

echo "Starting gateway proxy (enforcement mode)..."
export GATEWAY_GITHUB_TOKEN="mock-github-token"
export GATEWAY_STRIPE_KEY="sk_test_mock_key"
export GATEWAY_GMAIL_TOKEN="mock-gmail-token"
$BINARY gateway --config "${ROOT_DIR}/config/gateway-test.yaml" --port "$PROXY_PORT" > /dev/null 2>&1 &
PROXY_PID=$!
sleep 1

# ============================================================
# 1. GitHub Adapter Tests (5 tests)
# ============================================================
echo ""
echo -e "${CYAN}--- 1. GitHub Adapter (5 tests) ---${NC}"

# 1.1 Allowed read - GET /github/user
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${PROXY_URL}/github/user")
assert_status "GET /github/user (allowed read)" 200 "$STATUS"

# 1.2 Blocked path - GET /github/repos/octocat/test/issues
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${PROXY_URL}/github/repos/octocat/test/issues")
assert_status "GET /github/repos/.../issues (blocked path)" 403 "$STATUS"

# 1.3 Blocked method - POST to GitHub
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${PROXY_URL}/github/repos/octocat/test/issues" \
    -H "Content-Type: application/json" -d '{"title":"test"}')
assert_status "POST /github/repos/.../issues (blocked method)" 403 "$STATUS"

# 1.4 Operation parsing - GET /github/user/repos returns data
RESP=$(curl -s "${PROXY_URL}/github/user/repos")
assert_contains "GET /github/user/repos returns repo list" '"name"' "$RESP"

# 1.5 Credential injection - check X-Received-Auth header
AUTH_HEADER=$(curl -s -D - -o /dev/null "${PROXY_URL}/github/user" 2>/dev/null | grep -i "X-Received-Auth" || echo "")
assert_contains "Credential injected (X-Received-Auth present)" "X-Received-Auth" "$AUTH_HEADER"

# ============================================================
# 2. Stripe Adapter Tests (6 tests)
# ============================================================
echo ""
echo -e "${CYAN}--- 2. Stripe Adapter (6 tests) ---${NC}"

# 2.1 Allowed read - GET /stripe/v1/charges
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${PROXY_URL}/stripe/v1/charges")
assert_status "GET /stripe/v1/charges (allowed read)" 200 "$STATUS"

# 2.2 Allowed charge within cap (intersection cap is 1000)
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${PROXY_URL}/stripe/v1/charges" \
    -H "Content-Type: application/x-www-form-urlencoded" -d "amount=800&currency=usd")
assert_status "POST /stripe/v1/charges amount=800 (within intersection cap)" 200 "$STATUS"

# 2.3 Blocked charge over intersection cap
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${PROXY_URL}/stripe/v1/charges" \
    -H "Content-Type: application/x-www-form-urlencoded" -d "amount=3000&currency=usd")
assert_status "POST /stripe/v1/charges amount=3000 (over intersection cap)" 403 "$STATUS"

# 2.4 Blocked operation - create_transfer
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${PROXY_URL}/stripe/v1/transfers" \
    -H "Content-Type: application/x-www-form-urlencoded" -d "amount=100&currency=usd")
assert_status "POST /stripe/v1/transfers (blocked operation)" 403 "$STATUS"

# 2.5 Blocked currency
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${PROXY_URL}/stripe/v1/charges" \
    -H "Content-Type: application/x-www-form-urlencoded" -d "amount=500&currency=gbp")
assert_status "POST /stripe/v1/charges currency=gbp (blocked currency)" 403 "$STATUS"

# 2.6 Blocked method - DELETE
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE "${PROXY_URL}/stripe/v1/subscriptions/sub_123")
assert_status "DELETE /stripe/v1/subscriptions (blocked method)" 403 "$STATUS"

# ============================================================
# 3. Gmail Adapter Tests (5 tests)
# ============================================================
echo ""
echo -e "${CYAN}--- 3. Gmail Adapter (5 tests) ---${NC}"

# 3.1 Allowed list
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${PROXY_URL}/gmail/gmail/v1/users/me/messages")
assert_status "GET /gmail/.../messages (allowed list)" 200 "$STATUS"

# 3.2 Allowed send to @acme.com
MIME_ACME=$(printf "To: user@acme.com\r\nSubject: Test\r\n\r\nHello" | base64 | tr '+/' '-_' | tr -d '=')
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${PROXY_URL}/gmail/gmail/v1/users/me/messages/send" \
    -H "Content-Type: application/json" -d "{\"raw\":\"${MIME_ACME}\"}")
assert_status "POST send_email to user@acme.com (allowed)" 200 "$STATUS"

# 3.3 Blocked send to external
MIME_EXT=$(printf "To: user@external.com\r\nSubject: Test\r\n\r\nHello" | base64 | tr '+/' '-_' | tr -d '=')
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${PROXY_URL}/gmail/gmail/v1/users/me/messages/send" \
    -H "Content-Type: application/json" -d "{\"raw\":\"${MIME_EXT}\"}")
assert_status "POST send_email to user@external.com (blocked)" 403 "$STATUS"

# 3.4 Blocked operation - modify_message
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${PROXY_URL}/gmail/gmail/v1/users/me/messages/msg1/modify" \
    -H "Content-Type: application/json" -d '{"addLabelIds":["UNREAD"]}')
assert_status "POST modify_message (blocked operation)" 403 "$STATUS"

# 3.5 Blocked method - DELETE
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE "${PROXY_URL}/gmail/gmail/v1/users/me/messages/msg1")
assert_status "DELETE /gmail/.../messages/msg1 (blocked method)" 403 "$STATUS"

# ============================================================
# 4. Intersection Policy Tests (3 tests)
# ============================================================
echo ""
echo -e "${CYAN}--- 4. Intersection Policies (3 tests) ---${NC}"

# 4.1 Stripe cap lowered with Gmail present (1000, not 5000)
RESP=$(curl -s -X POST "${PROXY_URL}/stripe/v1/charges" \
    -H "Content-Type: application/x-www-form-urlencoded" -d "amount=1500&currency=usd")
assert_contains "Stripe cap=1000 (lowered by intersection)" "amount 1500 exceeds max_amount_cents 1000" "$RESP"

# 4.2 Amount just at the cap works
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${PROXY_URL}/stripe/v1/charges" \
    -H "Content-Type: application/x-www-form-urlencoded" -d "amount=999&currency=usd")
assert_status "POST /stripe/v1/charges amount=999 (just under intersection cap)" 200 "$STATUS"

# 4.3 Verify the reason references the correct cap value
RESP=$(curl -s -X POST "${PROXY_URL}/stripe/v1/charges" \
    -H "Content-Type: application/x-www-form-urlencoded" -d "amount=5000&currency=usd")
assert_contains "Reason references cap 1000 (not base 5000)" "max_amount_cents 1000" "$RESP"

# ============================================================
# 5. Learning Mode Tests (3 tests)
# ============================================================
echo ""
echo -e "${CYAN}--- 5. Learning Mode (3 tests) ---${NC}"

# Stop enforcement proxy, start learning mode
kill "$PROXY_PID" 2>/dev/null || true
wait "$PROXY_PID" 2>/dev/null || true
PROXY_PID=""
sleep 0.5

$BINARY gateway --config "${ROOT_DIR}/config/gateway-test-learning.yaml" --port "$PROXY_PORT" > /dev/null 2>&1 &
PROXY_PID=$!
sleep 1

# 5.1 Blocked request is forwarded in learning mode
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${PROXY_URL}/github/repos/octocat/test/issues" \
    -H "Content-Type: application/json" -d '{"title":"learning test"}')
TOTAL=$((TOTAL + 1))
if [ "$STATUS" -ne 403 ]; then
    echo -e "  ${GREEN}PASS${NC} POST in learning mode NOT blocked (HTTP $STATUS)"
    PASS=$((PASS + 1))
else
    echo -e "  ${RED}FAIL${NC} POST in learning mode should NOT be 403 (HTTP $STATUS)"
    FAIL=$((FAIL + 1))
fi

# 5.2 Audit shows would_block
sleep 0.5
AUDIT_RESP=$(curl -s "${PROXY_URL}/internal/audit?decision=allowed&limit=1")
assert_contains "Audit entry has would_block" "would_block" "$AUDIT_RESP"

# 5.3 Allowed request logged normally
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${PROXY_URL}/github/user")
TOTAL=$((TOTAL + 1))
if [ "$STATUS" -ne 403 ]; then
    echo -e "  ${GREEN}PASS${NC} GET /github/user in learning mode (HTTP $STATUS)"
    PASS=$((PASS + 1))
else
    echo -e "  ${RED}FAIL${NC} GET /github/user should be allowed in learning mode (HTTP $STATUS)"
    FAIL=$((FAIL + 1))
fi

# ============================================================
# 6. Credential Harvesting Tests (2 tests)
# ============================================================
echo ""
echo -e "${CYAN}--- 6. Credential Harvesting (2 tests) ---${NC}"

# Send requests with credentials
curl -s "${PROXY_URL}/github/user" -H "Authorization: Bearer test-harvest-token-1" > /dev/null 2>&1 || true
curl -s "${PROXY_URL}/stripe/v1/charges" -H "Authorization: Bearer test-harvest-token-2" > /dev/null 2>&1 || true
curl -s "${PROXY_URL}/github/user" -H "Authorization: Bearer test-harvest-token-1" > /dev/null 2>&1 || true

# 6.1 Credentials detected
HARVESTED=$(curl -s "${PROXY_URL}/internal/harvested")
CRED_COUNT=$(echo "$HARVESTED" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('credentials',[])))" 2>/dev/null || echo "0")
TOTAL=$((TOTAL + 1))
if [ "$CRED_COUNT" -ge 2 ]; then
    echo -e "  ${GREEN}PASS${NC} Harvested $CRED_COUNT credentials"
    PASS=$((PASS + 1))
else
    echo -e "  ${RED}FAIL${NC} Expected >= 2 credentials, got $CRED_COUNT"
    FAIL=$((FAIL + 1))
fi

# 6.2 Stats accurate
STATS=$(curl -s "${PROXY_URL}/internal/harvested/stats")
assert_contains "Harvest stats show providers" "total_providers" "$STATS"

# ============================================================
# 7. Behavior Profiling Tests (2 tests)
# ============================================================
echo ""
echo -e "${CYAN}--- 7. Behavior Profiling (2 tests) ---${NC}"

# 7.1 Profile reflects requests
PROFILE=$(curl -s "${PROXY_URL}/internal/profile/test-learning-001")
assert_contains "Profile shows total_requests" "total_requests" "$PROFILE"

# 7.2 Suggestions generated
SUGGEST=$(curl -s "${PROXY_URL}/internal/profile/test-learning-001/suggest")
assert_contains "Suggestions endpoint returns data" "suggestions" "$SUGGEST"

# ============================================================
# 8. Audit Tests (3 tests)
# ============================================================
echo ""
echo -e "${CYAN}--- 8. Audit (3 tests) ---${NC}"

# 8.1 Query by provider
AUDIT_GH=$(curl -s "${PROXY_URL}/internal/audit?provider=github")
GH_COUNT=$(echo "$AUDIT_GH" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('events',[])))" 2>/dev/null || echo "0")
TOTAL=$((TOTAL + 1))
if [ "$GH_COUNT" -ge 1 ]; then
    echo -e "  ${GREEN}PASS${NC} Audit by provider=github returns $GH_COUNT events"
    PASS=$((PASS + 1))
else
    echo -e "  ${RED}FAIL${NC} Expected >= 1 github events, got $GH_COUNT"
    FAIL=$((FAIL + 1))
fi

# 8.2 Query by decision
AUDIT_ALLOWED=$(curl -s "${PROXY_URL}/internal/audit?decision=allowed")
ALLOWED_COUNT=$(echo "$AUDIT_ALLOWED" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('events',[])))" 2>/dev/null || echo "0")
TOTAL=$((TOTAL + 1))
if [ "$ALLOWED_COUNT" -ge 1 ]; then
    echo -e "  ${GREEN}PASS${NC} Audit by decision=allowed returns $ALLOWED_COUNT events"
    PASS=$((PASS + 1))
else
    echo -e "  ${RED}FAIL${NC} Expected >= 1 allowed events, got $ALLOWED_COUNT"
    FAIL=$((FAIL + 1))
fi

# 8.3 Stats match
AUDIT_STATS=$(curl -s "${PROXY_URL}/internal/audit/stats")
assert_contains "Audit stats contain total_events" "total_events" "$AUDIT_STATS"

# ============================================================
# 9. Unknown Provider Test (1 test)
# ============================================================
echo ""
echo -e "${CYAN}--- 9. Unknown Provider (1 test) ---${NC}"

# Stop learning proxy, restart enforcement proxy for this test
kill "$PROXY_PID" 2>/dev/null || true
wait "$PROXY_PID" 2>/dev/null || true
PROXY_PID=""
sleep 0.5

$BINARY gateway --config "${ROOT_DIR}/config/gateway-test.yaml" --port "$PROXY_PORT" > /dev/null 2>&1 &
PROXY_PID=$!
sleep 1

STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${PROXY_URL}/unknown/endpoint")
assert_status "GET /unknown/endpoint (unknown provider)" 404 "$STATUS"

# ============================================================
# Summary
# ============================================================
echo ""
echo "============================================"
if [ "$FAIL" -eq 0 ]; then
    echo -e "  ${GREEN}ALL TESTS PASSED: ${PASS}/${TOTAL}${NC}"
else
    echo -e "  ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC} out of ${TOTAL}"
fi
echo "============================================"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
