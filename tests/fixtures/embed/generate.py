#!/usr/bin/env python3
"""Generates the reference streams `tests/embed.rs` decodes, with CPython's
zlib (and by hand for the stream zlib would never produce). The inputs are
derived deterministically, by the same rules as `data()` in the test, so
only the compressed side is stored. Re-run to regenerate; the outputs are
reproducible."""
import gzip, os, struct, zlib

here = os.path.dirname(os.path.abspath(__file__))


def text(n):
    out = bytearray()
    i = 0
    while len(out) < n:
        out += f"line {i}: the quick brown fox jumps over the lazy dog\n".encode()
        i += 1
    return bytes(out[:n])


def random(n, seed=0x12345678):
    out = bytearray()
    x = seed
    for _ in range(n):
        x ^= (x << 13) & 0xFFFFFFFF
        x ^= x >> 17
        x ^= (x << 5) & 0xFFFFFFFF
        out.append(x & 0xFF)
    return bytes(out)


def far():
    # zlib's encoder reaches back 32506 bytes at most, so the far match this
    # produces is at 32000; `far_exact()` is the one at deflate's full 32768.
    r = random(32000)
    return r + r


def far_exact_data():
    """What `far_exact()` decodes to: a 256-byte ramp repeated to 33022
    bytes, then ten bytes copied from exactly 32768 back."""
    data = bytearray(bytes(range(256)))
    while len(data) < 256 + 258 * 127:
        data.append(data[-256])
    for _ in range(10):
        data.append(data[-32768])
    return bytes(data)


def write(name, data):
    with open(os.path.join(here, name), "wb") as f:
        f.write(data)


def deflate(data, level, wbits):
    c = zlib.compressobj(level, zlib.DEFLATED, wbits)
    return c.compress(data) + c.flush()


class Bits:
    """LSB-first bit writer, deflate style."""

    def __init__(self):
        self.out = bytearray()
        self.acc = 0
        self.n = 0

    def bits(self, value, count):
        self.acc |= value << self.n
        self.n += count
        while self.n >= 8:
            self.out.append(self.acc & 0xFF)
            self.acc >>= 8
            self.n -= 8

    def code(self, code, length):
        # Huffman codes go most significant bit first.
        for i in range(length - 1, -1, -1):
            self.bits((code >> i) & 1, 1)

    def finish(self):
        if self.n:
            self.bits(0, 8 - self.n)
        return bytes(self.out)


def bomb(matches):
    """A raw deflate stream of one dynamic block whose codes are as short as
    deflate allows: a 1-bit code for length 258 and a 1-bit code for
    distance 1, so every two bits of input stand for 258 bytes of output.
    Decodes to b'a' * (1 + 258 * matches)."""
    w = Bits()
    w.bits(1, 1)  # BFINAL
    w.bits(2, 2)  # BTYPE = dynamic
    w.bits(286 - 257, 5)  # HLIT
    w.bits(1 - 1, 5)  # HDIST
    # Code length code: symbols 0, 1, 2 and 18, two bits each, given in
    # deflate's order up to symbol 1 (index 17).
    order = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15]
    cl_len = {0: 2, 1: 2, 2: 2, 18: 2}
    w.bits(18 - 4, 4)  # HCLEN
    for sym in order[:18]:
        w.bits(cl_len.get(sym, 0), 3)
    cl_code = {0: 0b00, 1: 0b01, 2: 0b10, 18: 0b11}

    def cl(sym):
        w.code(cl_code[sym], 2)

    def zeros(n):
        while n:
            run = min(n, 138)
            assert run >= 11
            cl(18)
            w.bits(run - 11, 7)
            n -= run

    # Literal/length lengths: 'a' (97) -> 2 bits, end of block -> 2 bits,
    # length 258 (285) -> 1 bit. Then the one distance length: 1 bit.
    zeros(97)
    cl(2)
    zeros(256 - 98)
    cl(2)
    zeros(285 - 257)
    cl(1)
    cl(1)
    # Canonical codes: 285 -> "0", 97 -> "10", 256 -> "11"; distance 0 -> "0".
    w.code(0b10, 2)  # 'a'
    for _ in range(matches):
        w.code(0, 1)  # length 258
        w.code(0, 1)  # distance 1
    w.code(0b11, 2)  # end of block
    return w.finish()


def fixed_literal(w, sym):
    if sym < 144:
        w.code(0x30 + sym, 8)
    else:
        w.code(0x190 + sym - 144, 9)


def far_exact():
    """A raw deflate stream, one fixed-Huffman block, whose last match
    reaches back exactly 32768 bytes: deflate's limit, which zlib's encoder
    never produces. Decodes to `far_exact_data()`."""
    w = Bits()
    w.bits(1, 1)  # BFINAL
    w.bits(1, 2)  # BTYPE = fixed
    for sym in range(256):
        fixed_literal(w, sym)
    for _ in range(127):
        w.code(0xC0 + 285 - 280, 8)  # length 258
        w.code(15, 5)  # distance code 15: base 193, 6 extra bits
        w.bits(256 - 193, 6)
    w.code(264 - 256, 7)  # length 10
    w.code(29, 5)  # distance code 29: base 24577, 13 extra bits
    w.bits(32768 - 24577, 13)
    w.code(0, 7)  # end of block
    return w.finish()


def gzip_fancy(data):
    """A gzip member with every optional header field set."""
    extra = b"\x41\x42\x04\x00abcd"
    head = bytearray(b"\x1f\x8b\x08")
    head.append(0x02 | 0x04 | 0x08 | 0x10)  # FHCRC FEXTRA FNAME FCOMMENT
    head += struct.pack("<IBB", 0x5F3E_1234, 0, 3)
    head += struct.pack("<H", len(extra)) + extra
    head += b"fancy.txt\x00"
    head += b"a comment, with bytes > 127: \xe9\xff\x00"
    head += struct.pack("<H", zlib.crc32(bytes(head)) & 0xFFFF)
    body = deflate(data, 6, -15)
    tail = struct.pack("<II", zlib.crc32(data) & 0xFFFFFFFF, len(data) & 0xFFFFFFFF)
    return bytes(head) + body + tail


T = text(60_000)
write("text_l9.zlib", zlib.compress(T, 9))
write("text_l1.zlib", zlib.compress(T, 1))
write("text_l0.zlib", zlib.compress(T, 0))
write("text_l6.deflate", deflate(T, 6, -15))
write("text_l6.gz", gzip.compress(T, 6, mtime=0))
write("text_fancy.gz", gzip_fancy(T))
write("random.zlib", zlib.compress(random(20_000), 6))
write("far.zlib", zlib.compress(far(), 9))
write("empty.zlib", zlib.compress(b"", 6))
write("empty.gz", gzip.compress(b"", 6, mtime=0))
write("bomb.deflate", bomb(2000))
write("far_exact.deflate", far_exact())

# Sanity: zlib agrees with the hand-made streams.
assert zlib.decompress(far_exact(), -15) == far_exact_data()
assert len(zlib.compress(far(), 9)) < 40_000, "the far match was not found"
assert zlib.decompress(bomb(2000), -15) == b"a" * (1 + 258 * 2000)
assert zlib.decompress(bomb(1), -15) == b"a" * 259
