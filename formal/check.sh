#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Gate the DMTAP formal models against EXPECTED.txt.
#
# run.sh RUNS the models and prints their output, but every invocation is
# `|| true`, so it exits 0 whether every property holds or one silently broke.
# That is the difference between a proof being *executed* and a proof being
# *enforced* — and an unenforced proof degrades into a claim in a README the
# moment the model or the spec moves underneath it.
#
# This script re-runs the models, extracts every RESULT line, and compares the
# verdicts to EXPECTED.txt. Any deviation in EITHER direction is a failure:
#   - a security query turning false is a regression;
#   - a non-vacuity control turning true means the model can no longer reach the
#     states it reasons about, so its "proofs" have gone vacuous while still
#     reporting success. See EXPECTED.txt for why that is the worse case.
#
# A THIRD direction also matters and used to go unchecked: the loop below only
# walks EXPECTED.txt looking for a matching RESULT line, so it only ever notices
# a query going MISSING or MISMATCHing. A *new* query — a `.pv` file edited to
# add one, or added to run.sh's MODELS list — produces a RESULT line that never
# gets compared to anything, so it could come back "false" (a broken security
# property) and the gate would still print "all N expected verdicts hold". That
# is the exact "examines only part of its subject" shape this gate exists to
# rule out elsewhere. So this script also runs the walk in reverse: every actual
# RESULT line must be claimed by some EXPECTED.txt row, and the two counts
# (rows in EXPECTED.txt, RESULT lines actually produced) must be equal — an
# EXPECT_ROWS-style assertion, not just a per-row diff.
#
# Usage:  ./check.sh          # run models, then gate
#         ./check.sh <log>    # gate an existing run.sh log without re-running
# Exit:   0 all verdicts as expected; 1 otherwise.
# ---------------------------------------------------------------------------
set -uo pipefail
cd "$(dirname "$0")"

EXPECTED="EXPECTED.txt"
[ -f "$EXPECTED" ] || { echo "missing $EXPECTED"; exit 1; }

if [ "$#" -ge 1 ]; then
  LOG="$1"
  echo "gating existing log: $LOG"
else
  LOG="$(mktemp -t proverif-check)"
  echo "running models (this takes a few minutes) ..."
  ./run.sh >"$LOG" 2>&1
fi

# Attribute each RESULT line to the model whose banner most recently preceded it.
ACTUAL="$(awk '/^== proverif/{m=$3} /^RESULT/{sub(/^RESULT /,""); print m"\t"$0}' "$LOG")"

fail=0
checked=0
while IFS= read -r line; do
  case "$line" in ''|\#*) continue ;; esac
  model=$(printf '%s' "$line" | awk '{print $1}')
  want=$(printf '%s' "$line"  | awk '{print $2}')
  # The query text is everything after the first two fields; it may contain
  # spaces, parens and "==>" so it is matched as a fixed substring, never a regex.
  query=$(printf '%s' "$line" | sed -E 's/^[^ ]+ +[^ ]+ +//')

  got=$(printf '%s\n' "$ACTUAL" \
        | grep -F "$model	" \
        | grep -F "$query" \
        | sed -E 's/.* is (true|false)\.?$/\1/' \
        | head -1)

  checked=$((checked + 1))
  if [ -z "$got" ]; then
    echo "MISSING  $model :: $query"
    echo "         no RESULT line matched — the query was renamed, removed, or the model failed to run"
    fail=1
  elif [ "$got" != "$want" ]; then
    echo "MISMATCH $model :: $query"
    echo "         expected $want, got $got"
    [ "$want" = "false" ] && echo "         NOTE: this is a non-vacuity control. Turning true means the model no longer reaches the state it reasons about — its other proofs may now be vacuous."
    fail=1
  fi
done < "$EXPECTED"

# Reverse pass: every RESULT line actually produced must be claimed by some row
# in EXPECTED.txt (same model, substring match on the query text). A line that
# claims none is a query EXPECTED.txt has never seen — new, renamed, or moved to
# a different model — and it is running completely ungated: nothing above this
# point ever compared its true/false verdict to anything.
produced=0
unexpected=0
while IFS= read -r aline; do
  [ -z "$aline" ] && continue
  produced=$((produced + 1))
  amodel=$(printf '%s' "$aline" | awk -F'\t' '{print $1}')
  atext=$(printf '%s'  "$aline" | awk -F'\t' '{print $2}')
  claimed=0
  while IFS= read -r eline; do
    case "$eline" in ''|\#*) continue ;; esac
    emodel=$(printf '%s' "$eline" | awk '{print $1}')
    equery=$(printf '%s' "$eline" | sed -E 's/^[^ ]+ +[^ ]+ +//')
    [ "$emodel" = "$amodel" ] || continue
    case "$atext" in *"$equery"*) claimed=1; break ;; esac
  done < "$EXPECTED"
  if [ "$claimed" -eq 0 ]; then
    echo "UNEXPECTED $amodel :: $atext"
    echo "           this RESULT line matches no row in EXPECTED.txt — a new or"
    echo "           renamed query is running with NOTHING gating its verdict."
    fail=1
    unexpected=$((unexpected + 1))
  fi
done <<< "$ACTUAL"

if [ "$produced" -ne "$checked" ]; then
  echo "COUNT MISMATCH: EXPECTED.txt has $checked row(s), the run produced $produced RESULT line(s)."
  echo "         Every declared query must have exactly one row here — add one (or remove a stale"
  echo "         one) rather than letting the counts drift apart silently."
  fail=1
fi

echo "----------------------------------------------------------------------"
if [ "$fail" -eq 0 ]; then
  echo "formal: all $checked expected verdicts hold ($produced RESULT lines produced, $unexpected unclaimed)"
else
  echo "formal: DEVIATION — see above ($checked expected, $produced produced, $unexpected unclaimed)"
fi
exit "$fail"
