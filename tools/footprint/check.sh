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
    printf '| %-26s | %6d / %-6d | %6d / %-6d | %5d / %-5d | %6d | %5d | %s |\n' \
        "$label" "$code" "$max_code" "$ram" "$max_ram" "$stack" "$max_stack" "$panics" "$data" "$verdict"
}

# The RAM ceilings are `compcol::embed::{DECODER_SIZE, ENCODER_SIZE}`, and
# their sum, or the same sums for the smaller sizes; the code and stack
# ceilings are the table in `compcol::embed`. Keep all three in sync.
DECODER=34816
ENCODER=6272
echo '| configuration              | code / max      | RAM / max       | stack / max   | panics | .data | verdict |'
echo '|----------------------------|----------------:|----------------:|--------------:|-------:|------:|---------|'
check 'gzip decode'                gzip-decode        4000 $DECODER 352
check 'zlib decode'                zlib-decode        4000 $DECODER 352
check 'raw deflate decode'         deflate-decode     3400 $DECODER 352
check 'gzip encode'                gzip-encode        1850 $ENCODER 256
check 'zlib encode'                zlib-encode        1850 $ENCODER 256
check 'raw deflate encode'         deflate-encode     1500 $ENCODER 224
check 'gzip encode + decode'       gzip-both          6200 $((DECODER + ENCODER)) 416
check 'gzip decode, 4 KiB window'  gzip-decode-4k     4000 $((4096 + 2048)) 352
check 'gzip encode, 1 KiB block'   gzip-encode-small  1850 $((1024 + 2 * 256 + 128)) 256
check 'gzip decompress'            gzip-decompress    2400 0 1400
check 'zlib decompress'            zlib-decompress    2200 0 1400
check 'raw deflate decompress'     deflate-decompress 2000 0 1400
check 'gzip decompressed length'   gzip-len           2200 0 1400
check 'gzip compress'              gzip-compress      1000 0 160
check 'zlib compress'              zlib-compress       950 0 160
check 'raw deflate compress'       deflate-compress    800 0 160
# `embed::flate`: no struct of its own, the memory is the caller's.
check 'flate gunzip'               flate-gunzip       2550 0 1450
check 'flate gunzip, streams'      flate-stream       2900 0 1600
check 'flate gunzip_len'           flate-len          2400 0 1450
check 'flate Decompressor'         flate-push         3650 0 1500
check 'flate gzip'                 flate-gzip         1050 0 192
check 'flate Compressor'           flate-compress-stream 1450 0 840
check 'flate BufferedCompressor'   flate-compress-push 1600 0 448
exit $status
