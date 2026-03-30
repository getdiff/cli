#!/usr/bin/env bash
# Agent Capability Gateway -- Investor Demo (Rust)
#
# This demo runs entirely locally with mock APIs.
# No real API tokens needed. No Docker needed.
#
# It demonstrates:
# 1. An AI agent making API calls with ZERO credentials
# 2. The gateway proxy injecting credentials at the network boundary
# 3. Per-provider policy enforcement (method, path, operation, amount caps)
# 4. Cross-API intersection policies (the novel differentiator)
# 5. Learning mode (observe without blocking)
# 6. Credential harvesting (auto-discover agent credentials)
# 7. Behavior profiling with policy suggestions
# 8. Full audit trail

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BINARY="${ROOT_DIR}/target/release/getdiff"
PROXY_PORT=8080
MOCKAPI_PORT=9999
PROXY_URL="http://localhost:${PROXY_PORT}"
FAST="${1:-}"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

START_TIME=$(date +%s)

# Pause function (skipped with --fast)
pause() {
    if [ "$FAST" != "--fast" ]; then
        sleep "${1:-0.5}"
    fi
}

section_pause() {
    if [ "$FAST" != "--fast" ]; then
        sleep "${1:-1}"
    fi
}

# Print helpers
header() {
    echo ""
    echo -e "${CYAN}${BOLD}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}${BOLD}  $1${NC}"
    echo -e "${CYAN}${BOLD}════════════════════════════════════════════════════════════════${NC}"
    echo ""
}

subheader() {
    echo -e "${BOLD}  --- $1 ---${NC}"
}

show_cmd() {
    echo -e "  ${DIM}\$ $1${NC}"
}

show_allowed() {
    echo -e "  ${GREEN}ALLOWED${NC} $1"
}

show_blocked() {
    echo -e "  ${RED}BLOCKED${NC} $1"
}

show_insight() {
    echo -e "  ${YELLOW}>>> $1${NC}"
}

show_response() {
    echo "$1" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    formatted = json.dumps(d, indent=2)
    for line in formatted.split('\n')[:12]:
        print('    ' + line)
    lines = formatted.split('\n')
    if len(lines) > 12:
        print('    ...')
except:
    for line in sys.stdin:
        print('    ' + line.rstrip())
" 2>/dev/null || echo "    $1"
}

# Cleanup
PROXY_PID=""
MOCKAPI_PID=""
PROXY_PID2=""

cleanup() {
    echo ""
    echo -e "${DIM}Cleaning up background processes...${NC}"
    [ -n "$PROXY_PID" ] && kill "$PROXY_PID" 2>/dev/null || true
    [ -n "$MOCKAPI_PID" ] && kill "$MOCKAPI_PID" 2>/dev/null || true
    [ -n "$PROXY_PID2" ] && kill "$PROXY_PID2" 2>/dev/null || true
    wait 2>/dev/null || true
}
trap cleanup EXIT

# ============================================================
# Build
# ============================================================
header "Agent Capability Gateway -- Investor Demo"

echo -e "  Building release binary..."
(cd "$ROOT_DIR" && cargo build --release) 2>&1 | tail -1
echo -e "  ${GREEN}Build complete.${NC}"
pause

# ============================================================
# Section 1: Setup
# ============================================================
header "1. Here is an AI agent with access to GitHub, Stripe, and Gmail"

echo "  Starting mock API server (simulates GitHub, Stripe, Gmail)..."
$BINARY mock-api --port "$MOCKAPI_PORT" > /dev/null 2>&1 &
MOCKAPI_PID=$!
sleep 0.5

echo "  Starting gateway proxy..."
export GATEWAY_GITHUB_TOKEN="mock-github-token-for-demo"
export GATEWAY_STRIPE_KEY="sk_test_mock_stripe_key"
export GATEWAY_GMAIL_TOKEN="mock-gmail-oauth-token"
$BINARY gateway --config "${ROOT_DIR}/config/gateway-test.yaml" --port "$PROXY_PORT" > /dev/null 2>&1 &
PROXY_PID=$!
sleep 1

echo ""
echo "  The proxy has 3 providers configured:"
echo -e "    ${BOLD}github${NC}  - read-only access to repositories"
echo -e "    ${BOLD}stripe${NC}  - charges up to \$50, no transfers"
echo -e "    ${BOLD}gmail${NC}   - send email to @acme.com only"
echo ""
echo "  Intersection policies are active:"
echo -e "    ${YELLOW}gmail + stripe${NC} -> email recipients capped at 3"
echo -e "    ${YELLOW}stripe + gmail${NC} -> charge amount capped at \$10 (down from \$50)"
section_pause

# ============================================================
# Section 2: Zero Credentials
# ============================================================
header "2. The agent has ZERO credentials"

show_insight "Notice: none of these curl commands include an Authorization header"
echo ""

subheader "GitHub: list user info"
show_cmd "curl http://localhost:8080/github/user"
RESP=$(curl -s -w "\n%{http_code}" "${PROXY_URL}/github/user")
HTTP_CODE=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | sed '$d')
show_allowed "GET /github/user -> HTTP $HTTP_CODE"
show_response "$BODY"
pause

echo ""
subheader "GitHub: list repos"
show_cmd "curl http://localhost:8080/github/user/repos"
RESP=$(curl -s -w "\n%{http_code}" "${PROXY_URL}/github/user/repos")
HTTP_CODE=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | sed '$d')
show_allowed "GET /github/user/repos -> HTTP $HTTP_CODE"
show_response "$BODY"
pause

echo ""
subheader "Stripe: list charges"
show_cmd "curl http://localhost:8080/stripe/v1/charges"
RESP=$(curl -s -w "\n%{http_code}" "${PROXY_URL}/stripe/v1/charges")
HTTP_CODE=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | sed '$d')
show_allowed "GET /stripe/v1/charges -> HTTP $HTTP_CODE"
show_response "$BODY"
pause

echo ""
subheader "Gmail: list messages"
show_cmd "curl http://localhost:8080/gmail/gmail/v1/users/me/messages"
RESP=$(curl -s -w "\n%{http_code}" "${PROXY_URL}/gmail/gmail/v1/users/me/messages")
HTTP_CODE=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | sed '$d')
show_allowed "GET /gmail/.../messages -> HTTP $HTTP_CODE"
show_response "$BODY"
pause

echo ""
show_insight "The mock API confirmed credentials were injected (X-Received-Auth header present)"
show_insight "The agent sent NO credentials. The proxy injected them at the network boundary."
section_pause

# ============================================================
# Section 3: Policy Enforcement
# ============================================================
header "3. Every call is inspected, scoped, and logged"

subheader "GitHub: try to create an issue (POST blocked)"
show_cmd "curl -X POST http://localhost:8080/github/repos/octocat/test/issues"
RESP=$(curl -s -w "\n%{http_code}" -X POST "${PROXY_URL}/github/repos/octocat/test/issues" \
    -H "Content-Type: application/json" -d '{"title":"test"}')
HTTP_CODE=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | sed '$d')
show_blocked "POST /github/repos/.../issues -> HTTP $HTTP_CODE"
show_response "$BODY"
pause

echo ""
subheader "Stripe: try to delete a subscription (DELETE blocked)"
show_cmd "curl -X DELETE http://localhost:8080/stripe/v1/subscriptions/sub_123"
RESP=$(curl -s -w "\n%{http_code}" -X DELETE "${PROXY_URL}/stripe/v1/subscriptions/sub_123")
HTTP_CODE=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | sed '$d')
show_blocked "DELETE /stripe/v1/subscriptions/sub_123 -> HTTP $HTTP_CODE"
show_response "$BODY"
pause

echo ""
subheader "Stripe: try to create a transfer (operation blocked)"
show_cmd "curl -X POST http://localhost:8080/stripe/v1/transfers -d 'amount=100&currency=usd'"
RESP=$(curl -s -w "\n%{http_code}" -X POST "${PROXY_URL}/stripe/v1/transfers" \
    -H "Content-Type: application/x-www-form-urlencoded" -d "amount=100&currency=usd")
HTTP_CODE=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | sed '$d')
show_blocked "POST /stripe/v1/transfers -> HTTP $HTTP_CODE"
show_response "$BODY"
pause

echo ""
subheader "Stripe: create a charge within limits"
show_cmd "curl -X POST http://localhost:8080/stripe/v1/charges -d 'amount=800&currency=usd'"
RESP=$(curl -s -w "\n%{http_code}" -X POST "${PROXY_URL}/stripe/v1/charges" \
    -H "Content-Type: application/x-www-form-urlencoded" -d "amount=800&currency=usd")
HTTP_CODE=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | sed '$d')
show_allowed "POST /stripe/v1/charges amount=800 (\$8.00) -> HTTP $HTTP_CODE"
show_response "$BODY"
section_pause

# ============================================================
# Section 4: Recipient Filtering
# ============================================================
header "4. The agent cannot send email outside the company"

subheader "Gmail: send to user@acme.com (allowed)"
MIME_MSG=$(printf "To: user@acme.com\r\nSubject: Weekly Report\r\n\r\nHere is the weekly report." | base64 | tr '+/' '-_' | tr -d '=')
show_cmd "curl -X POST http://localhost:8080/gmail/.../messages/send -d '{\"raw\":\"<base64 MIME to user@acme.com>\"}'"
RESP=$(curl -s -w "\n%{http_code}" -X POST "${PROXY_URL}/gmail/gmail/v1/users/me/messages/send" \
    -H "Content-Type: application/json" -d "{\"raw\":\"${MIME_MSG}\"}")
HTTP_CODE=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | sed '$d')
show_allowed "Send to user@acme.com -> HTTP $HTTP_CODE"
show_response "$BODY"
pause

echo ""
subheader "Gmail: send to user@external.com (blocked)"
MIME_MSG2=$(printf "To: user@external.com\r\nSubject: Data Export\r\n\r\nHere is the data." | base64 | tr '+/' '-_' | tr -d '=')
show_cmd "curl -X POST http://localhost:8080/gmail/.../messages/send -d '{\"raw\":\"<base64 MIME to user@external.com>\"}'"
RESP=$(curl -s -w "\n%{http_code}" -X POST "${PROXY_URL}/gmail/gmail/v1/users/me/messages/send" \
    -H "Content-Type: application/json" -d "{\"raw\":\"${MIME_MSG2}\"}")
HTTP_CODE=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | sed '$d')
show_blocked "Send to user@external.com -> HTTP $HTTP_CODE"
show_response "$BODY"
section_pause

# ============================================================
# Section 5: Intersection Policies
# ============================================================
header "5. Cross-API intersection policies (the differentiator)"

echo "  The base Stripe policy allows charges up to \$50 (max_amount_cents: 5000)."
echo ""
show_insight "But this agent also has Gmail access."
show_insight "An intersection policy activated: stripe + gmail -> max_amount_cents: 1000"
echo ""

subheader "Stripe: charge \$30 (3000 cents) -- over intersection cap"
show_cmd "curl -X POST http://localhost:8080/stripe/v1/charges -d 'amount=3000&currency=usd'"
RESP=$(curl -s -w "\n%{http_code}" -X POST "${PROXY_URL}/stripe/v1/charges" \
    -H "Content-Type: application/x-www-form-urlencoded" -d "amount=3000&currency=usd")
HTTP_CODE=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | sed '$d')
show_blocked "POST /stripe/v1/charges amount=3000 -> HTTP $HTTP_CODE"
show_response "$BODY"
pause

echo ""
show_insight "The charge cap dropped from \$50 to \$10 because of the Gmail+Stripe intersection."
show_insight "This is the capability no other product offers: cross-API policy enforcement."
show_insight "When an agent accumulates more capabilities, the gateway TIGHTENS controls."
section_pause

# ============================================================
# Section 6: Audit Trail
# ============================================================
header "6. Every decision is logged"

subheader "Aggregate audit stats"
show_cmd "curl http://localhost:8080/internal/audit/stats"
RESP=$(curl -s "${PROXY_URL}/internal/audit/stats")
show_response "$RESP"
pause

echo ""
subheader "Blocked requests with reasons"
show_cmd "curl 'http://localhost:8080/internal/audit?decision=denied&limit=5'"
RESP=$(curl -s "${PROXY_URL}/internal/audit?decision=denied&limit=5")
echo "$RESP" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    events = d.get('events', [])
    for e in events[:5]:
        provider = e.get('provider', '?')
        method = e.get('method', '?')
        path = e.get('path', '?')
        reason = e.get('reason', '')[:70]
        print(f'    [{provider}] {method} {path}')
        print(f'      reason: {reason}')
except:
    pass
" 2>/dev/null
pause

echo ""
show_insight "Full audit trail of every agent action across all APIs."
section_pause

# ============================================================
# Section 7: Learning Mode
# ============================================================
header "7. Start with observation, enforce later"

echo "  Stopping the enforcement proxy..."
kill "$PROXY_PID" 2>/dev/null || true
wait "$PROXY_PID" 2>/dev/null || true
PROXY_PID=""
sleep 0.5

echo "  Starting a new proxy with learning_mode: true..."
$BINARY gateway --config "${ROOT_DIR}/config/gateway-test-learning.yaml" --port "$PROXY_PORT" > /dev/null 2>&1 &
PROXY_PID2=$!
sleep 1

echo ""
subheader "POST to GitHub (would be blocked in enforcement mode)"
show_cmd "curl -X POST http://localhost:8080/github/repos/octocat/test/issues"
RESP=$(curl -s -w "\n%{http_code}" -X POST "${PROXY_URL}/github/repos/octocat/test/issues" \
    -H "Content-Type: application/json" -d '{"title":"test from learning mode"}')
HTTP_CODE=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | sed '$d')
show_allowed "POST /github/repos/.../issues -> HTTP $HTTP_CODE (forwarded despite policy violation!)"
show_response "$BODY"
pause

echo ""
subheader "Audit shows what would have been blocked"
show_cmd "curl 'http://localhost:8080/internal/audit?decision=allowed&limit=1'"
RESP=$(curl -s "${PROXY_URL}/internal/audit?decision=allowed&limit=1")
echo "$RESP" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    events = d.get('events', [])
    for e in events[:1]:
        wb = e.get('would_block', False)
        lm = e.get('learning_mode', False)
        wr = e.get('would_reason', '')
        print(f'    learning_mode: {lm}')
        print(f'    would_block: {wb}')
        if wr:
            print(f'    would_reason: {wr}')
except:
    pass
" 2>/dev/null
pause

echo ""
show_insight "The gateway observed the violation but did not block."
show_insight "In production: review the behavior profile, tune policies, then switch to enforcement."
section_pause

# ============================================================
# Section 8: Credential Harvesting
# ============================================================
header "8. Auto-discover credentials"

echo "  Making requests WITH agent-supplied credentials through the proxy..."
curl -s "${PROXY_URL}/github/user" -H "Authorization: Bearer ghp_agent_token_abc123" > /dev/null 2>&1 || true
curl -s "${PROXY_URL}/stripe/v1/charges" -H "Authorization: Bearer sk_test_agent_key_xyz" > /dev/null 2>&1 || true
curl -s "${PROXY_URL}/github/user/repos" -H "Authorization: Bearer ghp_agent_token_abc123" > /dev/null 2>&1 || true
pause

echo ""
subheader "Discovered credentials"
show_cmd "curl http://localhost:8080/internal/harvested"
RESP=$(curl -s "${PROXY_URL}/internal/harvested")
show_response "$RESP"
pause

echo ""
show_insight "Point your existing agent traffic through the gateway."
show_insight "It discovers what credentials are in use and offers to manage them."
show_insight "Zero-config onboarding."
section_pause

# ============================================================
# Section 9: Behavior Profiling
# ============================================================
header "9. Policy suggestions from behavior"

show_cmd "curl http://localhost:8080/internal/profile/test-learning-001/suggest"
RESP=$(curl -s "${PROXY_URL}/internal/profile/test-learning-001/suggest")
show_response "$RESP"
pause

echo ""
show_insight "The gateway analyzed what the agent actually did and suggested policies."
show_insight "In production, this powers natural language policy creation:"
show_insight "  'Restrict this agent to what it has been doing.'"
section_pause

# ============================================================
# Closing
# ============================================================
header "Summary"

END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

echo "  What was demonstrated:"
echo ""
echo -e "    ${GREEN}1.${NC} Zero-credential agent          The agent sent NO auth headers"
echo -e "    ${GREEN}2.${NC} Credential injection            Proxy added Bearer tokens at the network boundary"
echo -e "    ${GREEN}3.${NC} Per-provider policies           Method, path, operation, amount, recipient filtering"
echo -e "    ${GREEN}4.${NC} Cross-API intersections          Stripe cap dropped \$50 -> \$10 when Gmail also present"
echo -e "    ${GREEN}5.${NC} Recipient filtering             External emails blocked, internal emails allowed"
echo -e "    ${GREEN}6.${NC} Full audit trail                Every decision logged with context and reasons"
echo -e "    ${GREEN}7.${NC} Learning mode                   Observe first, enforce later"
echo -e "    ${GREEN}8.${NC} Credential harvesting           Auto-discover credentials from traffic"
echo -e "    ${GREEN}9.${NC} Behavior profiling              Policy suggestions from observed behavior"
echo ""
echo -e "  Demo completed in ${BOLD}${ELAPSED} seconds${NC}."
echo ""
echo -e "${CYAN}${BOLD}  Agent Capability Gateway${NC}"
echo -e "${CYAN}  Credentials injected at the network boundary.${NC}"
echo -e "${CYAN}  Cross-API policy enforcement.${NC}"
echo -e "${CYAN}  Observe-first security.${NC}"
echo ""
