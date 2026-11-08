#!/bin/bash
# Three real-client outage models. Cores 6 and 7 are not present on this VM
# (online CPUs are 0-3); pin to 2,3 and nice -n 19. At most two models at once.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
export PATH="/usr/sbin:/usr/bin:/bin:$PATH"

run_one() {
  local model=$1
  local ns="rstm-${model}"
  ip netns del "$ns" >/dev/null 2>&1 || true
  ip netns add "$ns"
  ip netns exec "$ns" python3 "$HERE/rst-run.py" "$model" "$OUT/$model"
  local rc=$?
  ip netns del "$ns" >/dev/null 2>&1 || true
  return "$rc"
}

if [ "${1:-}" = "__one" ]; then
  OUT=${3:?missing out dir}
  mkdir -p "$OUT"
  run_one "$2"
  exit $?
fi

OUT=${1:-/opt/cursor/artifacts/rst-path}
mkdir -p "$OUT"
fail=0
nice -n 19 taskset -c 2,3 bash "$0" __one persistent "$OUT" &
p1=$!
nice -n 19 taskset -c 2,3 bash "$0" __one local-rst "$OUT" &
p2=$!
wait "$p1" || fail=1
wait "$p2" || fail=1
nice -n 19 taskset -c 2,3 bash "$0" __one restored "$OUT" || fail=1
exit "$fail"
