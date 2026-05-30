#!/usr/bin/env python3
"""Reference LZSS encoder/decoder, port of Okumura's LZSS.C (public domain).

Wire framing: 4-byte LE uncompressed length + payload.
"""
import struct, sys

N = 4096
F = 18
THRESHOLD = 2
NUL = 0x20

def encode(data: bytes) -> bytes:
    # Faithful port of Okumura's LZSS.C Encode() but with a brute-force
    # match finder (no binary tree).
    text_buf = bytearray([NUL] * (N + F - 1))
    code_buf = bytearray(17)
    code_buf[0] = 0
    code_buf_ptr = 1
    mask = 1
    out = bytearray()

    s = 0
    r = N - F
    in_pos = 0
    n_data = len(data)

    # Read F bytes into the look-ahead buffer.
    length = 0
    while length < F and in_pos < n_data:
        text_buf[r + length] = data[in_pos]
        in_pos += 1
        length += 1
    if length == 0:
        return struct.pack('<I', 0)

    while length > 0:
        # Find longest match in text_buf for lookahead at r..r+length.
        # Brute force over ring positions 0..N-1, excluding the
        # lookahead region [r, r+length).
        best_len = 0
        best_pos = 0
        for i in range(N):
            # Compute if i is in lookahead window [r, r+length) mod N.
            offset_into_la = (i - r) & (N - 1)
            if offset_into_la < length:
                continue
            k = 0
            while k < length and text_buf[(i + k) & (N - 1)] == text_buf[r + k]:
                k += 1
                if k >= F:
                    break
            if k > best_len:
                best_len = k
                best_pos = i
                if k >= F:
                    break
            elif k == best_len and i < best_pos:
                best_pos = i

        if best_len <= THRESHOLD:
            best_len = 1
            code_buf[0] |= mask
            code_buf[code_buf_ptr] = text_buf[r]
            code_buf_ptr += 1
        else:
            code_buf[code_buf_ptr] = best_pos & 0xFF
            code_buf_ptr += 1
            code_buf[code_buf_ptr] = ((best_pos >> 4) & 0xF0) | ((best_len - (THRESHOLD + 1)) & 0x0F)
            code_buf_ptr += 1

        mask = (mask << 1) & 0xFF
        if mask == 0:
            out.extend(code_buf[:code_buf_ptr])
            code_buf[0] = 0
            code_buf_ptr = 1
            mask = 1

        # Shift the window by best_len bytes.
        last_match_length = best_len
        i = 0
        while i < last_match_length and in_pos < n_data:
            c = data[in_pos]
            in_pos += 1
            # Slot s gets the new byte; also mirror into wraparound zone.
            text_buf[s] = c
            if s < F - 1:
                text_buf[s + N] = c
            s = (s + 1) & (N - 1)
            r = (r + 1) & (N - 1)
            i += 1
        # If we ran out of input but the lookahead still has bytes,
        # keep shifting (length shrinks).
        while i < last_match_length:
            s = (s + 1) & (N - 1)
            r = (r + 1) & (N - 1)
            length -= 1
            if length == 0:
                break
            i += 1

    if code_buf_ptr > 1:
        out.extend(code_buf[:code_buf_ptr])
    return struct.pack('<I', n_data) + bytes(out)


def decode(data: bytes) -> bytes:
    if len(data) < 4:
        raise ValueError("truncated header")
    length = struct.unpack('<I', data[:4])[0]
    out = bytearray()
    buf = bytearray([NUL] * N)
    r = N - F
    pos = 4
    flags = 0
    flag_bits = 0
    while pos < len(data) and len(out) < length:
        if flag_bits == 0:
            flags = data[pos]
            pos += 1
            flag_bits = 8
        if flags & 1:
            if pos >= len(data):
                break
            b = data[pos]
            pos += 1
            out.append(b)
            buf[r] = b
            r = (r + 1) & (N - 1)
        else:
            if pos + 1 >= len(data):
                break
            lo = data[pos]
            hi = data[pos + 1]
            pos += 2
            off = lo | ((hi & 0xF0) << 4)
            mlen = (hi & 0x0F) + THRESHOLD + 1
            for k in range(mlen):
                b = buf[(off + k) & (N - 1)]
                out.append(b)
                buf[r] = b
                r = (r + 1) & (N - 1)
                if len(out) >= length:
                    break
        flags >>= 1
        flag_bits -= 1
    return bytes(out[:length])


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "encode":
        sys.stdout.buffer.write(encode(sys.stdin.buffer.read()))
    elif cmd == "decode":
        sys.stdout.buffer.write(decode(sys.stdin.buffer.read()))
