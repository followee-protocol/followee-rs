#!/usr/bin/env bash
# Three-relay local demonstration (IMPLEMENTATION.md section 13, Milestone 4).
#
# Starts three real `followee relay serve` processes on loopback port-0
# sockets with isolated SQLite databases, then proves through the production
# binary surfaces (never in-process imitations) that:
#
#   1. the relays begin with different partial views;
#   2. one relay synchronizes a newer current record without historical
#      events, while both serve processes keep running (cross-process);
#   3. invalid or losing synchronized/published input does not alter
#      current state;
#   4. a client follows a Ref path, and the final Full candidate is
#      verified locally;
#   5. lazy path compression affects only routing state;
#   6. restart preserves relay identity, generations, and peer cursors; and
#   7. every exchange uses the production HTTP/CBOR client and relay.
#
# Readiness comes from each server's one-line machine-readable startup
# object; supervision uses recorded PIDs and an EXIT trap. No arbitrary
# sleeps.
#
# Environment:
#   FOLLOWEE_BIN      path to the `followee` binary        (default: cargo build)
#   HOUSEKEEPING_BIN  path to the relay_housekeeping example (default: cargo build)
#   DEMO_WORKDIR      working directory                     (default: mktemp -d)

set -euo pipefail

say() { printf '\n== %s\n' "$*"; }

if [[ -z "${FOLLOWEE_BIN:-}" ]]; then
  cargo build --quiet --bin followee
  FOLLOWEE_BIN="$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')/debug/followee"
fi
if [[ -z "${HOUSEKEEPING_BIN:-}" ]]; then
  cargo build --quiet --example relay_housekeeping
  HOUSEKEEPING_BIN="$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')/debug/examples/relay_housekeeping"
fi

WORK="${DEMO_WORKDIR:-$(mktemp -d)}"
mkdir -p "$WORK"
PIDS=()
cleanup() {
  for pid in "${PIDS[@]:-}"; do
    kill -TERM "$pid" 2>/dev/null || true
  done
  for pid in "${PIDS[@]:-}"; do
    wait "$pid" 2>/dev/null || true
  done
}
trap cleanup EXIT

# jget FILE EXPR — evaluate a python expression over parsed JSON `j`.
jget() {
  python3 -c 'import json,sys; j=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$1" "$2"
}
# jassert FILE EXPR MESSAGE — assert a python expression over parsed JSON `j`.
jassert() {
  python3 -c 'import json,sys; j=json.load(open(sys.argv[1]));
assert eval(sys.argv[2]), sys.argv[3] + ": " + json.dumps(j)' "$1" "$2" "$3"
}

# start_relay NAME [DB] — starts a serve process; readiness is its startup
# line. DB defaults to NAME.db; a restart passes the original database.
start_relay() {
  local name="$1"
  local db="${2:-$name.db}"
  local fifo="$WORK/$name.startup"
  "$FOLLOWEE_BIN" relay serve \
    --database "$WORK/$db" \
    --listen 127.0.0.1:0 \
    >"$fifo.out" 2>"$WORK/$name.err" &
  PIDS+=("$!")
  eval "PID_$name=$!"
  # Explicit readiness signal: the one-line startup JSON object.
  local tries=0
  while ! [[ -s "$fifo.out" ]]; do
    tries=$((tries + 1))
    [[ $tries -lt 200 ]] || { echo "relay $name never became ready"; exit 1; }
    # Bounded poll of the readiness signal, not a fixed arbitrary sleep.
    python3 -c 'import time; time.sleep(0.05)'
  done
  head -n1 "$fifo.out" > "$WORK/$name.startup.json"
  eval "BASE_$name=\"$(jget "$WORK/$name.startup.json" 'j["baseUri"]')\""
  eval "RELAYID_$name=\"$(jget "$WORK/$name.startup.json" 'j["relayId"]')\""
  eval "CURSORGEN_$name=\"$(jget "$WORK/$name.startup.json" 'j["cursorGeneration"]')\""
}

say "starting three relays with isolated databases"
start_relay A
start_relay B
start_relay C
echo "A=$BASE_A B=$BASE_B C=$BASE_C"

say "creating a fresh identity and signing two records"
"$FOLLOWEE_BIN" identity create \
  --root-key "$WORK/root.seed" --revocation-key "$WORK/rev.seed" \
  --identity "$WORK/identity.json" > "$WORK/create.json" 2>/dev/null
DID="$(jget "$WORK/create.json" 'j["did"]')"
echo '{"displayName":"Demo Identity","summary":"older"}' > "$WORK/contact1.json"
echo '{"displayName":"Demo Identity","summary":"newer"}' > "$WORK/contact2.json"
"$FOLLOWEE_BIN" record sign-root --identity "$WORK/identity.json" --key "$WORK/root.seed" \
  --contact "$WORK/contact1.json" --out "$WORK/r1.cose" --timestamp-ms 1785589200000 > "$WORK/r1.json"
"$FOLLOWEE_BIN" record sign-root --identity "$WORK/identity.json" --key "$WORK/root.seed" \
  --contact "$WORK/contact2.json" --out "$WORK/r2.cose" --timestamp-ms 1785589201000 > "$WORK/r2.json"
R2_HEX="$(python3 -c 'print(open("'"$WORK"'/r2.cose","rb").read().hex())')"

say "seeding different partial views: R1 on B; R1 then R2 on A; nothing on C"
"$FOLLOWEE_BIN" relay publish --relay "$BASE_B" --record "$WORK/r1.cose" --policy development > "$WORK/pub-b1.json"
jassert "$WORK/pub-b1.json" 'j["status"]=="admitted"' "B admits R1"
"$FOLLOWEE_BIN" relay publish --relay "$BASE_A" --record "$WORK/r1.cose" --policy development > "$WORK/pub-a1.json"
"$FOLLOWEE_BIN" relay publish --relay "$BASE_A" --record "$WORK/r2.cose" --policy development > "$WORK/pub-a2.json"
jassert "$WORK/pub-a2.json" 'j["status"]=="admitted"' "A admits R2"

"$FOLLOWEE_BIN" relay resolve --relay "$BASE_A" --did "$DID" --policy development > "$WORK/res-a.json"
"$FOLLOWEE_BIN" relay resolve --relay "$BASE_B" --did "$DID" --policy development > "$WORK/res-b.json"
"$FOLLOWEE_BIN" relay resolve --relay "$BASE_C" --did "$DID" --policy development > "$WORK/res-c.json"
jassert "$WORK/res-a.json" 'j["results"][0]["recordHex"]=="'"$R2_HEX"'"' "A serves R2"
jassert "$WORK/res-b.json" 'j["results"][0]["verified"] and j["results"][0]["timestampMs"]==1785589200000' "B serves the older R1"
jassert "$WORK/res-c.json" 'j["results"][0]["kind"]=="absent"' "C has no view yet"
echo "the three relays hold different partial views"

say "B synchronizes A's newer current record (current state, no history)"
"$FOLLOWEE_BIN" relay sync --database "$WORK/B.db" --peer "$BASE_A" --policy development > "$WORK/sync-b1.json"
jassert "$WORK/sync-b1.json" 'len(j["admitted"])==1 and j["admitted"][0]["did"]=="'"$DID"'"' "exactly the one current tuple crossed"
jassert "$WORK/sync-b1.json" 'j["finalCursorHex"] is not None' "peer cursor stored"
CURSOR1="$(jget "$WORK/sync-b1.json" 'j["finalCursorHex"]')"
"$FOLLOWEE_BIN" relay resolve --relay "$BASE_B" --did "$DID" --policy development > "$WORK/res-b2.json"
jassert "$WORK/res-b2.json" 'j["results"][0]["recordHex"]=="'"$R2_HEX"'"' "B now serves R2, learned without any event history"

say "losing and invalid input do not alter current state"
"$FOLLOWEE_BIN" relay publish --relay "$BASE_B" --record "$WORK/r1.cose" --policy development > "$WORK/pub-b-losing.json"
jassert "$WORK/pub-b-losing.json" 'j["status"]=="noChange"' "the older R1 is a valid losing record"
python3 -c '
data = bytearray(open("'"$WORK"'/r2.cose","rb").read())
data[-1] ^= 0x01
open("'"$WORK"'/corrupt.cose","wb").write(bytes(data))
'
if "$FOLLOWEE_BIN" relay publish --relay "$BASE_B" --record "$WORK/corrupt.cose" --policy development > "$WORK/pub-b-bad.json"; then
  echo "corrupted record was not rejected"; exit 1
fi
jassert "$WORK/pub-b-bad.json" 'j["error"]["symbol"]=="publishRejected"' "protocol rejection is symbolically distinct"
"$FOLLOWEE_BIN" relay resolve --relay "$BASE_B" --did "$DID" --policy development > "$WORK/res-b3.json"
jassert "$WORK/res-b3.json" 'j["results"][0]["recordHex"]=="'"$R2_HEX"'"' "B's current state is unchanged"

say "seeding C with a Ref to A (operator housekeeping over the store contract)"
"$FOLLOWEE_BIN" relay publish --relay "$BASE_C" --record "$WORK/r2.cose" --policy development > "$WORK/pub-c.json"
jassert "$WORK/pub-c.json" 'j["status"]=="admitted"' "C admits R2 as Full"
"$HOUSEKEEPING_BIN" set-directory "$WORK/C.db" 0 "$RELAYID_A" "$BASE_A" > "$WORK/hk-dir.json"
"$HOUSEKEEPING_BIN" convert-to-ref "$WORK/C.db" "$DID" 0 > "$WORK/hk-ref.json"
"$FOLLOWEE_BIN" relay resolve --relay "$BASE_C" --did "$DID" --policy development > "$WORK/res-c2.json"
jassert "$WORK/res-c2.json" 'j["results"][0]["kind"]=="ref" and j["results"][0]["relayIndex"]==0' "C now answers with a Ref"

say "a client follows the Ref from C to A and verifies the Full locally"
"$FOLLOWEE_BIN" resolve --did "$DID" --relay "$BASE_C" --policy development --state "$WORK/state.json" > "$WORK/resolve1.json"
jassert "$WORK/resolve1.json" 'j["outcome"]=="found"' "resolution succeeds"
jassert "$WORK/resolve1.json" 'any(d["event"]=="ref" for d in j["diagnostics"])' "a Ref path was followed"
jassert "$WORK/resolve1.json" 'j["record"]["recordHex"]=="'"$R2_HEX"'"' "the final Full candidate verified locally is R2"
jassert "$WORK/resolve1.json" 'j["record"]["source"]=="'"$BASE_A"'"' "the winner came from A via the reference"
jassert "$WORK/resolve1.json" 'j["compressedRoute"]=="'"$BASE_A"'"' "lazy path compression stored the direct route"

say "path compression affected only routing state"
jassert "$WORK/state.json" 'j["dids"]["'"$DID"'"]["route"]=="'"$BASE_A"'"' "state file: routing hint only"
jassert "$WORK/state.json" 'j["dids"]["'"$DID"'"]["authorityState"]=="root"' "identity state untouched by compression"
"$FOLLOWEE_BIN" resolve --did "$DID" --relay "$BASE_C" --policy development --state "$WORK/state.json" > "$WORK/resolve2.json"
jassert "$WORK/resolve2.json" 'j["diagnostics"][0]["relay"]=="'"$BASE_A"'"' "the compressed route is consulted first"
jassert "$WORK/resolve2.json" 'j["outcome"]=="found" and j["record"]["recordHex"]=="'"$R2_HEX"'"' "same verified record"

say "restart preserves relay identity, generations, and peer cursors"
kill -TERM "$PID_B"
wait "$PID_B" || true
start_relay B2 B.db
[[ "$RELAYID_B" == "$RELAYID_B2" ]] || { echo "relay id changed across restart"; exit 1; }
[[ "$CURSORGEN_B" == "$CURSORGEN_B2" ]] || { echo "cursor generation changed across restart"; exit 1; }
"$FOLLOWEE_BIN" relay resolve --relay "$BASE_B2" --did "$DID" --policy development > "$WORK/res-b4.json"
jassert "$WORK/res-b4.json" 'j["results"][0]["recordHex"]=="'"$R2_HEX"'"' "identity state survived the restart"
# The stored peer cursor survives: an incremental sync from A finds nothing
# new at that exact cursor position.
"$FOLLOWEE_BIN" relay sync --database "$WORK/B.db" --peer "$BASE_A" --policy development > "$WORK/sync-b2.json"
jassert "$WORK/sync-b2.json" 'len(j["admitted"])==0' "nothing new after the stored cursor"
jassert "$WORK/sync-b2.json" 'j["finalCursorHex"]=="'"$CURSOR1"'"' "the exact peer cursor survived the restart"

say "demonstration complete"
echo "workdir: $WORK"
