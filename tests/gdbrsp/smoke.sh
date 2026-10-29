#!/usr/bin/env bash
# Drives the GDB protocol core (pcsx2/DebugTools/GdbRsp.cpp) with the real PS2
# toolchain gdb, against tests/gdbrsp/fake_target.cpp - no emulator involved.
#
#   tests/gdbrsp/smoke.sh <mips64r5900el-ps2-elf-gdb> <unstripped game ELF> [port]
#
# The ELF needs DWARF and a main() (a debug build's bin/<name>.elf.sym). The
# checks are what a debugging session leans on: the register layout matches
# gdb's built-in one (it has no XML support; an FPR is 8 bytes there, holding
# the EE's single in its low word), memory and disassembly read, `break main`
# + continue stops with a source line, stepi works, a hardware watchpoint
# reports, a fault arrives as SIGSEGV, and detach ends the session.
set -euo pipefail

GDB=${1:?usage: smoke.sh <gdb> <elf> [port]}
ELF=${2:?usage: smoke.sh <gdb> <elf> [port]}
PORT=${3:-23950}
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
WORK=$(mktemp -d)
trap 'kill "$FAKE_PID" 2>/dev/null || true; rm -rf "$WORK"' EXIT

g++ -std=c++20 -O1 -Wall -Wextra -pthread -o "$WORK/fake_target" \
  "$HERE/fake_target.cpp" "$ROOT/pcsx2/DebugTools/GdbRsp.cpp"

"$WORK/fake_target" "$ELF" "$PORT" --fault >"$WORK/fake.log" 2>&1 &
FAKE_PID=$!
sleep 0.5

cat >"$WORK/session.gdb" <<EOF
set pagination off
set confirm off
set remotetimeout 10
set mipsfpu single
target remote localhost:$PORT
info registers pc sp ra sr
p/x \$f0
x/2i \$pc
break main
continue
stepi
p/x \$pc
delete 1
watch *(int *)0x00500000
continue
delete
continue
p/x \$bad
detach
EOF

set +e
timeout 120 "$GDB" -batch -nx -x "$WORK/session.gdb" "$ELF" >"$WORK/gdb.log" 2>&1
GDB_STATUS=$?
set -e
# The fake exits when its session ends; never wait on it past a moment.
sleep 0.5
kill "$FAKE_PID" 2>/dev/null || true
wait "$FAKE_PID" 2>/dev/null || true

cat "$WORK/gdb.log"
echo "----- fake target -----"
cat "$WORK/fake.log"
echo "-----------------------"

fail=0
expect() {
  if grep -Eq -- "$2" "$WORK/gdb.log"; then
    echo "PASS  $1"
  else
    echo "FAIL  $1 (no match for: $2)"
    fail=1
  fi
}
expect "connected and read registers" '^pc: 0x100e78'
expect "an FPR carries the single in its low word" '^\$1 = 0x3fc00000$'
expect "disassembly reads code memory" '=> 0x[0-9a-f]+'
expect "break main stops with a source line" 'Breakpoint 1, (0x[0-9a-f]+ in )?main ?\(.*\) at .*main\.cpp:[0-9]+'
expect "stepi moves pc one instruction" '^\$2 = 0x44202c$'
expect "a watchpoint hit reports the change" '^New value = [0-9]+$'
expect "a fault arrives as SIGSEGV" 'SIGSEGV'
expect "badvaddr reads the faulting address" '= 0xdead0000'
expect "detach ends the session" 'Inferior 1 \(Remote target\) detached'
[ "$GDB_STATUS" -eq 0 ] || { echo "FAIL  gdb exited with $GDB_STATUS"; fail=1; }

if [ "$fail" -eq 0 ]; then echo "SMOKE: PASS"; else echo "SMOKE: FAIL"; fi
exit "$fail"
