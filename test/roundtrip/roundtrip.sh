#!/bin/bash
# Round-trip test: one cadir handed between OpenVox Server and openvox-ca.
#
# The filesystem backend's promise (docs/storage-backends.md, "Sharing the
# cadir with OpenVox Server") is that the same directory works with either CA
# as it stands. This drives that on ONE directory, four times over:
#
#   1. OpenVox Server creates the CA, issues, and revokes.
#   2. openvox-ca starts on it with no import, issues, and revokes and cleans
#      by name certificates OpenVox Server issued.
#   3. OpenVox Server starts on the untouched directory, sees all of that, and
#      revokes and cleans by name certificates openvox-ca issued.
#   4. openvox-ca refuses to start until rebuild-inventory-hmac has run -- the
#      one documented preparation step -- then issues, and revokes and cleans
#      by name certificates OpenVox Server issued in phase 3.
#
# Each phase checks the other's revocations are still in force, and that
# inventory.txt only ever grew: each phase's file must be a byte prefix of the
# next, in OpenVox Server's line format throughout.
#
# Runs on the host and reaches into the two services with `compose exec`,
# because the hand-over -- one CA stopping, the other starting on what it left
# -- is the thing under test, and a container cannot do that to its peers.
# Run from the project root (`mage test:migration` does).
#
# Output: TAP format.  Exit 0 when all pass, exit 1 if any fail.

set -uo pipefail

# shellcheck source=test/failure-log.sh
. test/failure-log.sh

# -- Container engine / compose detection ----------------------------------
# The same resolution as composeCmd() in magefile.go and test/puppet/
# puppet-stack.sh, kept as a copy for the reason test/failure-log.sh gives.
if [[ -n "${CONTAINER_ENGINE:-}" ]]; then
    _ENGINE="$CONTAINER_ENGINE"
elif command -v podman &>/dev/null; then
    _ENGINE=podman
elif command -v docker &>/dev/null; then
    _ENGINE=docker
else
    printf 'Error: neither podman nor docker found\n' >&2
    exit 1
fi
if [[ "$_ENGINE" == podman ]] && command -v podman-compose &>/dev/null; then
    _COMPOSE=(podman-compose -f test/compose-roundtrip.yml)
elif docker compose version &>/dev/null 2>&1; then
    _COMPOSE=(docker compose -f test/compose-roundtrip.yml)
elif command -v docker-compose &>/dev/null; then
    _COMPOSE=(docker-compose -f test/compose-roundtrip.yml)
else
    printf 'Error: no compose tool found; install podman-compose or docker compose\n' >&2
    exit 1
fi

# -- Configuration -----------------------------------------------------------
CADIR=/etc/puppetlabs/puppetserver/ca
OVCA_URL=http://127.0.0.1:8140
WORK_DIR=$(mktemp -d /tmp/openvox-ca-roundtrip.XXXXXX)

# Readiness bounds. OpenVox Server is a JVM and takes most of a minute to
# start; openvox-ca takes a second or two.
OVS_READY_ATTEMPTS=90
OVCA_READY_ATTEMPTS=30
READY_SLEEP=2

# -- TAP helpers --------------------------------------------------------------
T=0
FAILURES=0

pass() {
    T=$(( T + 1 ))
    printf 'ok %d - %s\n' "$T" "$1"
}

fail() {
    T=$(( T + 1 ))
    FAILURES=$(( FAILURES + 1 ))
    printf 'not ok %d - %s\n' "$T" "$1"
    [ -n "${2:-}" ] && printf '  # %s\n' "$(printf '%s' "$2" | tr '\n' ' ' | head -c 600)"
    return 0
}

finish() {
    printf '\n1..%d\n' "$T"
    printf '# Results: %d passed, %d failed out of %d\n' \
        $(( T - FAILURES )) "$FAILURES" "$T"
}

cleanup() {
    local _rc=$?
    if [ "$_rc" -ne 0 ] || [ "$FAILURES" -gt 0 ]; then
        printf '\n# Run failed (exit %d, %d failed assertions) -- service logs follow\n' \
            "$_rc" "$FAILURES" >&2
        failure_log_dump ovs "${_COMPOSE[@]}" >&2
        failure_log_dump ovca "${_COMPOSE[@]}" >&2
    fi
    "${_COMPOSE[@]}" down --volumes >/dev/null 2>&1
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

# bail ends the run when a phase cannot go on: every later phase stands on the
# directory this one should have left.
bail() {
    fail "$1" "${2:-}"
    finish
    printf 'Bail out! %s\n' "$1"
    exit 1
}

# -- Service helpers -----------------------------------------------------------
ovs_sh()  { "${_COMPOSE[@]}" exec -T ovs  sh -c "$1"; }
ovca_sh() { "${_COMPOSE[@]}" exec -T ovca bash -c "$1"; }

wait_ready() {  # service attempts probe-command
    local _i
    for _i in $(seq 1 "$2"); do
        "${_COMPOSE[@]}" exec -T "$1" sh -c "$3" >/dev/null 2>&1 && return 0
        sleep "$READY_SLEEP"
    done
    return 1
}

start_ovs() {
    "${_COMPOSE[@]}" up -d ovs >/dev/null 2>&1
    wait_ready ovs "$OVS_READY_ATTEMPTS" \
        'curl -sfk https://localhost:8140/status/v1/simple | grep -q running'
}

start_ovca() {
    "${_COMPOSE[@]}" up -d ovca >/dev/null 2>&1
    wait_ready ovca "$OVCA_READY_ATTEMPTS" "curl -sf ${OVCA_URL}/healthz/ready"
}

stop() { "${_COMPOSE[@]}" stop "$1" >/dev/null 2>&1; }

# The inventory as the directory holds it, read through whichever service is up.
inventory() { "${_COMPOSE[@]}" exec -T "$1" cat "$CADIR/inventory.txt"; }

# check_inventory asserts inventory.txt only grew since the last phase, and is
# in OpenVox Server's format throughout.
check_inventory() {  # phase service
    local _now="$WORK_DIR/inventory.$1" _prev="$WORK_DIR/inventory.$(( $1 - 1 ))"
    inventory "$2" > "$_now" 2>&1
    if [ -f "$_prev" ]; then
        if [ "$(head -c "$(wc -c < "$_prev")" "$_now" | cksum)" = "$(cksum < "$_prev")" ]; then
            pass "Phase $1: inventory.txt kept every earlier line byte for byte"
        else
            fail "Phase $1: inventory.txt kept every earlier line byte for byte" \
                 "before: $(cat "$_prev") after: $(cat "$_now")"
        fi
    fi
    local _bad
    _bad=$(grep -v -E '^0x[0-9A-F]{4,} [0-9T:-]+UTC [0-9T:-]+UTC /CN=' "$_now")
    [ -z "$_bad" ] \
        && pass "Phase $1: every inventory line is in OpenVox Server's format" \
        || fail "Phase $1: every inventory line is in OpenVox Server's format" "other lines: $_bad"
}

# -- OpenVox Server operations -----------------------------------------------
ovs_generate() { ovs_sh "puppetserver ca generate --certname $1" >/dev/null 2>&1; }
ovs_revoke()   { ovs_sh "puppetserver ca revoke --certname $1" 2>&1; }
ovs_clean()    { ovs_sh "puppetserver ca clean --certname $1" 2>&1; }
# ovs_listed reports which section of `puppetserver ca list --all` names $1.
ovs_listed() {
    ovs_sh 'puppetserver ca list --all' 2>&1 | awk -v n="$1" '
        /^Signed Certificates:/  { s = "signed" }
        /^Revoked Certificates:/ { s = "revoked" }
        /^Requested Certificates:/ { s = "requested" }
        $1 == n { print s }'
}

# -- openvox-ca operations ---------------------------------------------------
ovca_issue() {  # certname -> HTTP status of the CSR submission
    ovca_sh "set -e; d=\$(mktemp -d)
        openssl req -new -newkey rsa:2048 -nodes -keyout \$d/k -subj /CN=$1 -out \$d/csr 2>/dev/null
        curl -s -o /dev/null -w '%{http_code}' -X PUT -H 'Content-Type: text/plain' \
            --data-binary @\$d/csr ${OVCA_URL}/puppet-ca/v1/certificate_request/$1"
}
ovca_revoke() {  # certname -> HTTP status
    ovca_sh "curl -s -o /dev/null -w '%{http_code}' -X PUT -H 'Content-Type: application/json' \
        -d '{\"desired_state\":\"revoked\"}' ${OVCA_URL}/puppet-ca/v1/certificate_status/$1"
}
ovca_clean() {  # certname -> HTTP status
    ovca_sh "curl -s -o /dev/null -w '%{http_code}' -X DELETE \
        ${OVCA_URL}/puppet-ca/v1/certificate_status/$1"
}
ovca_cert_code() {  # certname -> HTTP status of fetching its certificate
    ovca_sh "curl -s -o /dev/null -w '%{http_code}' ${OVCA_URL}/puppet-ca/v1/certificate/$1"
}
ovca_state() {  # certname -> "signed" / "revoked" / response
    ovca_sh "curl -s ${OVCA_URL}/puppet-ca/v1/certificate_status/$1" 2>&1 \
        | grep -o '"state":"[a-z]*"' | cut -d'"' -f4
}
# ovca_crl_lists reports whether the CRL openvox-ca serves lists $1's serial.
# The serial, not the words "Revoked Certificates": see the migration suite's
# 6e for why.
ovca_crl_lists() {  # certname
    ovca_sh "s=\$(openssl x509 -noout -serial -in $CADIR/signed/$1.pem | cut -d= -f2)
        curl -s ${OVCA_URL}/puppet-ca/v1/certificate_revocation_list/ca \
            | openssl crl -noout -text | grep -qi \"serial number: *0*\${s#0}\\b\""
}

expect_state() {  # phase certname want
    local _got
    _got=$(ovca_state "$2")
    [ "$_got" = "$3" ] \
        && pass "Phase $1: openvox-ca reports $2 as $3" \
        || fail "Phase $1: openvox-ca reports $2 as $3" "got [$_got]"
}

expect_ovs_listed() {  # phase certname want ("" for not listed at all)
    local _got _what="lists $2 as $3"
    [ -z "$3" ] && _what="no longer lists $2, which was cleaned"
    _got=$(ovs_listed "$2")
    [ "$_got" = "$3" ] \
        && pass "Phase $1: OpenVox Server $_what" \
        || fail "Phase $1: OpenVox Server $_what" "got [$_got]"
}

"${_COMPOSE[@]}" down --volumes >/dev/null 2>&1

# ═════════════════════════════════════════════════════════════════════════════
# Phase 1 -- OpenVox Server creates the CA, issues and revokes
# ═════════════════════════════════════════════════════════════════════════════
printf '# Phase 1 -- OpenVox Server creates the CA\n'

start_ovs || bail "Phase 1: OpenVox Server starts" "not ready after $OVS_READY_ATTEMPTS probes"
pass "Phase 1: OpenVox Server starts and creates its CA"

for n in a1.example.com a2.example.com a3.example.com; do
    ovs_generate "$n" \
        && pass "Phase 1: OpenVox Server issues $n" \
        || fail "Phase 1: OpenVox Server issues $n"
done
ovs_revoke a1.example.com >/dev/null
expect_ovs_listed 1 a1.example.com revoked
check_inventory 1 ovs
stop ovs

# ═════════════════════════════════════════════════════════════════════════════
# Phase 2 -- openvox-ca on the same directory, with no import
# ═════════════════════════════════════════════════════════════════════════════
printf '\n# Phase 2 -- openvox-ca starts on OpenVox Server'"'"'s cadir\n'

start_ovca || bail "Phase 2: openvox-ca starts on OpenVox Server's cadir with no import" \
    "not ready after $OVCA_READY_ATTEMPTS probes"
pass "Phase 2: openvox-ca starts on OpenVox Server's cadir with no import"

expect_state 2 a1.example.com revoked
expect_state 2 a2.example.com signed
for n in b1.example.com b2.example.com b3.example.com; do
    _code=$(ovca_issue "$n")
    [ "$_code" = "200" ] && [ "$(ovca_state "$n")" = "signed" ] \
        && pass "Phase 2: openvox-ca issues $n" \
        || fail "Phase 2: openvox-ca issues $n" "CSR submission status $_code"
done
for n in a2.example.com b1.example.com; do
    _code=$(ovca_revoke "$n")
    [ "$_code" = "204" ] \
        && pass "Phase 2: openvox-ca revokes $n by name" \
        || fail "Phase 2: openvox-ca revokes $n by name" "status $_code"
done
ovca_crl_lists a2.example.com \
    && pass "Phase 2: the CRL lists the serial OpenVox Server gave a2.example.com" \
    || fail "Phase 2: the CRL lists the serial OpenVox Server gave a2.example.com"
_code=$(ovca_clean a3.example.com)
[ "$_code" = "204" ] && [ "$(ovca_cert_code a3.example.com)" = "404" ] \
    && pass "Phase 2: openvox-ca cleans a3.example.com, which OpenVox Server issued" \
    || fail "Phase 2: openvox-ca cleans a3.example.com, which OpenVox Server issued" "status $_code"
check_inventory 2 ovca
stop ovca

# ═════════════════════════════════════════════════════════════════════════════
# Phase 3 -- OpenVox Server on the untouched directory
# ═════════════════════════════════════════════════════════════════════════════
printf '\n# Phase 3 -- OpenVox Server starts on what openvox-ca left\n'

start_ovs || bail "Phase 3: OpenVox Server starts on the untouched cadir" \
    "not ready after $OVS_READY_ATTEMPTS probes"
pass "Phase 3: OpenVox Server starts on the untouched cadir"

expect_ovs_listed 3 a2.example.com revoked
expect_ovs_listed 3 b1.example.com revoked
expect_ovs_listed 3 b2.example.com signed
expect_ovs_listed 3 b3.example.com signed
expect_ovs_listed 3 a3.example.com ""
ovs_revoke b2.example.com >/dev/null
expect_ovs_listed 3 b2.example.com revoked
ovs_clean b3.example.com >/dev/null
expect_ovs_listed 3 b3.example.com ""
for n in c1.example.com c2.example.com; do
    ovs_generate "$n" \
        && pass "Phase 3: OpenVox Server issues $n" \
        || fail "Phase 3: OpenVox Server issues $n"
done
check_inventory 3 ovs
stop ovs

# ═════════════════════════════════════════════════════════════════════════════
# Phase 4 -- back to openvox-ca, after the one preparation step
# ═════════════════════════════════════════════════════════════════════════════
printf '\n# Phase 4 -- openvox-ca returns\n'

# OpenVox Server appended c1 and c2 without updating .inventory.hmac, so the
# server must refuse until the value is rebuilt. Run in the foreground under a
# bound: a refusal exits at once, a server that started would run until 124.
_refusal=$(timeout 60 "${_COMPOSE[@]}" run --rm --no-deps -T ovca 2>&1)
_refusal_rc=$?
if [ "$_refusal_rc" -ne 0 ] && [ "$_refusal_rc" -ne 124 ] &&
   printf '%s' "$_refusal" | grep -q 'inventory integrity check failed'; then
    pass "Phase 4: openvox-ca refuses to start until the HMAC is rebuilt"
else
    fail "Phase 4: openvox-ca refuses to start until the HMAC is rebuilt" \
         "exit $_refusal_rc: $(printf '%s' "$_refusal" | tail -5)"
fi

_rebuild=$("${_COMPOSE[@]}" run --rm --no-deps -T ovca \
    rebuild-inventory-hmac --cadir="$CADIR" --yes-re-bless 2>&1)
_rebuild_rc=$?
[ "$_rebuild_rc" -eq 0 ] \
    && pass "Phase 4: rebuild-inventory-hmac --yes-re-bless succeeds" \
    || fail "Phase 4: rebuild-inventory-hmac --yes-re-bless succeeds" \
            "exit $_rebuild_rc: $(printf '%s' "$_rebuild" | tail -5)"

start_ovca || bail "Phase 4: openvox-ca starts after the rebuild" \
    "not ready after $OVCA_READY_ATTEMPTS probes"
pass "Phase 4: openvox-ca starts after the rebuild"

expect_state 4 b2.example.com revoked
expect_state 4 c1.example.com signed
[ "$(ovca_cert_code b3.example.com)" = "404" ] \
    && pass "Phase 4: openvox-ca no longer serves b3.example.com, which OpenVox Server cleaned" \
    || fail "Phase 4: openvox-ca no longer serves b3.example.com, which OpenVox Server cleaned"
_code=$(ovca_issue d1.example.com)
[ "$_code" = "200" ] && [ "$(ovca_state d1.example.com)" = "signed" ] \
    && pass "Phase 4: openvox-ca issues d1.example.com" \
    || fail "Phase 4: openvox-ca issues d1.example.com" "CSR submission status $_code"
for n in c1.example.com d1.example.com; do
    _code=$(ovca_revoke "$n")
    [ "$_code" = "204" ] \
        && pass "Phase 4: openvox-ca revokes $n by name" \
        || fail "Phase 4: openvox-ca revokes $n by name" "status $_code"
done
ovca_crl_lists c1.example.com \
    && pass "Phase 4: the CRL lists the serial OpenVox Server gave c1.example.com" \
    || fail "Phase 4: the CRL lists the serial OpenVox Server gave c1.example.com"
_code=$(ovca_clean c2.example.com)
[ "$_code" = "204" ] && [ "$(ovca_cert_code c2.example.com)" = "404" ] \
    && pass "Phase 4: openvox-ca cleans c2.example.com, which OpenVox Server issued" \
    || fail "Phase 4: openvox-ca cleans c2.example.com, which OpenVox Server issued" "status $_code"
check_inventory 4 ovca

finish
[ "$FAILURES" -eq 0 ]
