#!/usr/bin/env python3
"""Bounds the stack a bare-metal Thumb binary uses, from its disassembly.

Each function's frame is what its prologue reserves: the registers it
pushes and what it subtracts from `sp`. Direct calls (`bl`, and `b` to
another function for tail calls) give the call graph, and the deepest path
from `entry` gives the bound. There are no indirect calls to miss: the
codecs are generic, not trait objects. Prints the deepest path, and with -v
every function's frame and callees.

    stack.py BINARY --objdump PATH [-v]
"""
import re, subprocess, sys

path = sys.argv[1]
verbose = "-v" in sys.argv
objdump = sys.argv[sys.argv.index("--objdump") + 1] if "--objdump" in sys.argv else "llvm-objdump"

text = subprocess.run(
    [objdump, "-d", "--demangle", "--no-show-raw-insn", path], capture_output=True, text=True, check=True
).stdout

HEAD = re.compile(r"^([0-9a-f]+) <(.+)>:$")
INSN = re.compile(r"^\s*[0-9a-f]+:\s+(\S+)\s*(.*)$")

frames, calls, order = {}, {}, []
name = None
prologue = True
for line in text.splitlines():
    m = HEAD.match(line)
    if m:
        name = m.group(2)
        order.append(name)
        frames[name] = 0
        calls[name] = set()
        prologue = True
        continue
    m = INSN.match(line)
    if not m or name is None:
        continue
    op, args = m.group(1), m.group(2)
    if prologue:
        if op in ("push", "push.w"):
            regs = args.strip("{}").split(",")
            count = 0
            for r in regs:
                r = r.strip()
                if "-" in r:
                    a, b = r.split("-")
                    count += int(b.strip("r")) - int(a.strip("r")) + 1
                else:
                    count += 1
            frames[name] += 4 * count
        elif op in ("vpush",):
            frames[name] += 8 * len(args.strip("{}").split(","))
        elif op in ("sub", "sub.w") and args.startswith("sp,"):
            frames[name] += int(args.split("#")[1], 0)
        elif op in ("pop", "pop.w", "add", "add.w", "bl", "blx", "bx") or op.startswith("b"):
            prologue = False
    if op in ("bl", "blx") or (op in ("b", "b.w") and "<" in args):
        target = re.search(r"<(.+)>", args)
        if target and target.group(1) != name and "+" not in target.group(1):
            calls[name].add(target.group(1))

if not frames:
    print("no functions found in the disassembly", file=sys.stderr)
    sys.exit(2)


def depth(fn, path):
    """The deepest stack below `fn` inclusive, and the chain that reaches it."""
    if fn in path:
        return float("inf"), path + [fn]  # recursion: unbounded
    best, best_chain = 0, []
    for callee in calls.get(fn, ()):
        if callee in frames:
            d, chain = depth(callee, path + [fn])
            if d > best:
                best, best_chain = d, chain
    return frames.get(fn, 0) + best, [fn] + best_chain


total, chain = depth("entry", [])
print(f"stack: deepest path from entry {total}, sum of frames {sum(frames.values())}")
if verbose:
    for fn in order:
        print(f"  {frames[fn]:6d}  {fn}  -> {', '.join(sorted(calls[fn]))}")
    print("deepest path: " + " > ".join(chain))
