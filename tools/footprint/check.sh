#!/bin/sh
# Builds a bare-metal binary around each `embed` codec, prints its code size,
# static RAM and stack (the deepest call path from `entry`, see stack.py),
# and fails if any exceeds the ceiling documented in `compcol::embed`, if any
# panic machinery gets linked, if any static RAM is needed beyond the codec
# struct itself, or if that struct does not land in `.bss` (a codec in a
# `static` must cost no flash).
#
# Needs the thumbv7em-none-eabi target and the llvm-tools component:
#     rustup target add thumbv7em-none-eabi
#     rustup component add llvm-tools
set -eu
cd "$(dirname "$0")"

TARGET=thumbv7em-none-eabi
TARGET_DIR=${CARGO_TARGET_DIR:-$PWD/target}
BIN=$TARGET_DIR/$TARGET/release/footprint
TOOLS=$(dirname "$(find "$(rustc --print sysroot)" -name 'llvm-size*' | head -n 1)")
export CARGO_TARGET_DIR=$TARGET_DIR
export RUSTFLAGS="-C link-arg=--gc-sections -C link-arg=--entry=entry"

status=0
check() {
    label=$1 feature=$2 max_code=$3 max_ram=$4 max_stack=$5
    cargo build --quiet --release --target $TARGET --features "$feature"

    # Berkeley format: text, data, bss on the second line.
    set -- $("$TOOLS/llvm-size" "$BIN" | tail -n 1)
    code=$1 data=$2 ram=$(($2 + $3))
    panics=$("$TOOLS/llvm-nm" --demangle "$BIN" | grep -ci panic || true)
    stack=$(python3 stack.py "$BIN" --objdump "$TOOLS/llvm-objdump" | sed 's/.*from entry \([0-9]*\).*/\1/')
    verdict=ok
    if [ "$code" -gt "$max_code" ] || [ "$ram" -gt "$max_ram" ] || [ "$stack" -gt "$max_stack" ] \
        || [ "$panics" -ne 0 ] || [ "$data" -ne 0 ]; then
        verdict=FAIL
        status=1
    fi
    printf '| %-22s | %6d / %-6d | %6d / %-6d | %5d / %-5d | %6d | %4d | %s |\n' \
        "$label" "$code" "$max_code" "$ram" "$max_ram" "$stack" "$max_stack" "$panics" "$data" "$verdict"
}

# The RAM ceilings are `compcol::embed::{DECODER_SIZE, ENCODER_SIZE}`, and
# their sum; the code and stack ceilings are the table in `compcol::embed`.
# Keep all three in sync.
DECODER=34816
ENCODER=11008
echo '| configuration          | code / max      | RAM / max       | stack / max | panics | .data | verdict |'
echo '|------------------------|----------------:|----------------:|------------:|-------:|------:|---------|'
check 'gzip decode'          gzip-decode    4600 $DECODER 256
check 'zlib decode'          zlib-decode    4600 $DECODER 256
check 'raw deflate decode'   deflate-decode 4300 $DECODER 256
check 'gzip encode'          gzip-encode    2000 $ENCODER 256
check 'zlib encode'          zlib-encode    2000 $ENCODER 256
check 'raw deflate encode'   deflate-encode 1700 $ENCODER 256
check 'gzip encode + decode' gzip-both      6500 $((DECODER + ENCODER)) 256
exit $status
