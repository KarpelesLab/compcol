#!/bin/sh
# Cross-checks the `embed` build of the deflate family against the standard
# one through the `compcol` CLI: what one build compresses, the other must
# decompress to the original, both ways, for gzip, zlib and raw deflate, on
# text, random bytes and an empty input. Catches a stream that the embed
# codecs would accept from each other but no one else would.
#
# Builds the CLI twice, in release mode, into target directories of its own.
set -eu
cd "$(dirname "$0")/.."

ROOT=${CARGO_TARGET_DIR:-$PWD/target}
STD=$ROOT/crosscheck-std
EMB=$ROOT/crosscheck-embed
cargo build --quiet --release --features factory,gzip,zlib,deflate --target-dir "$STD"
cargo build --quiet --release --features factory,gzip,zlib,deflate,embed --target-dir "$EMB"
STD=$STD/release/compcol
EMB=$EMB/release/compcol

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Inputs: a text that compresses well (with far back-references for the
# standard encoder to find), incompressible bytes, and nothing.
awk 'BEGIN { for (i = 0; i < 200000; i++) printf "line %d: the quick brown fox jumps over the lazy dog\n", i }' > "$work/text"
head -c 300000 /dev/urandom > "$work/random"
: > "$work/empty"

status=0
for input in text random empty; do
    for algo in gzip zlib deflate; do
        for pair in "std:emb" "emb:std"; do
            from=${pair%%:*} to=${pair##*:}
            case $from in std) enc=$STD ;; *) enc=$EMB ;; esac
            case $to in std) dec=$STD ;; *) dec=$EMB ;; esac
            "$enc" -t $algo -c "$work/$input" > "$work/packed"
            if "$dec" -t $algo -d -c "$work/packed" > "$work/unpacked" && cmp -s "$work/$input" "$work/unpacked"; then
                verdict=ok
            else
                verdict=FAIL
                status=1
            fi
            printf '%-7s %-8s %s -> %s  %8d -> %8d  %s\n' "$algo" "$input" "$from" "$to" \
                "$(wc -c < "$work/$input")" "$(wc -c < "$work/packed")" "$verdict"
        done
    done
done
exit $status
