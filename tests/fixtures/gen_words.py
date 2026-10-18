import sys
WORDS=[b"alpha ",b"beta ",b"gamma ",b"delta ",b"epsilon ",b"zeta ",b"eta ",b"theta "]
def gen(n):
    x=1; out=bytearray()
    while len(out)<n:
        x=(x*1103515245+12345)&0xFFFFFFFF
        out+=WORDS[(x>>16)&7]
    return bytes(out[:n])
n=int(sys.argv[1]); sys.stdout.buffer.write(gen(n))
