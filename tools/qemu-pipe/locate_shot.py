"""Locate the daemon's prim/hold pipes in a 4-chunk physical dump and print the
shot parameters (bufs, pipe_inode_info, ring, next write slot).

prim  = the pipe whose matching slot is spent   (offset=9, len=0, ops=0)
hold  = the pipe whose matching slot is live    (offset=0, len=9, ops=anon)

Usage: locate_shot.py --page 0x103046000 [--chunk glram0.bin ...] [--base 0x40000000]
"""
import struct
import sys

DMAP, MEMSTART, VMEM, SPS = 0xffffff8000000000, 0x40000000, 0xfffffffe00000000, 0x40
P_HEAD, P_TAIL, P_MAX, P_RING, P_BUFS, P_TMP = 0x60, 0x64, 0x68, 0x6c, 0xa8, 0x90
RINGS = (1, 2, 4, 8, 16, 32, 64, 128, 256)


def main():
    chunks, base, pages, scan_start, scan_len = [], 0x40000000, [], 0x100000000, 0x4000000
    a = sys.argv[1:]
    i = 0
    while i < len(a):
        if a[i] == '--chunk':
            chunks.append(a[i + 1]); i += 2
        elif a[i] == '--base':
            base = int(a[i + 1], 0); i += 2
        elif a[i] == '--page':
            pages.append(int(a[i + 1], 0)); i += 2
        elif a[i] == '--start':
            scan_start = int(a[i + 1], 0); i += 2
        elif a[i] == '--len':
            scan_len = int(a[i + 1], 0); i += 2
        else:
            print('unknown arg', a[i]); return 2

    # chunk files are 1 GiB each, consecutive
    parts, phys = [], base
    for p in chunks:
        parts.append((phys, open(p, 'rb').read()))
        phys += 1 << 30

    def rd(p, n):
        for b, d in parts:
            if b <= p and p + n <= b + len(d):
                o = p - b
                return d[o:o + n]
        return None

    vptrs = {p: VMEM + ((p - MEMSTART) >> 12) * SPS for p in pages}
    print('targets: ' + ', '.join('phys 0x%x -> struct page 0x%x' % (p, v) for p, v in vptrs.items()))

    region = None
    for b, d in parts:
        if b <= scan_start < b + len(d):
            region = d[scan_start - b:scan_start - b + scan_len]
    if region is None:
        print('scan range not in dump'); return 2

    hits = []
    for o in range(0, len(region) - 0xc0, 8):
        head, tail, mx, ring = struct.unpack_from('<IIII', region, o + P_HEAD)
        if ring not in RINGS or mx == 0 or mx > ring or tail > head or head > ring:
            continue
        bufs = struct.unpack_from('<Q', region, o + P_BUFS)[0]
        if not (DMAP <= bufs < DMAP + 0x100000000):
            continue
        for k in range(ring):
            slot = rd(base + (bufs - DMAP) + MEMSTART - base + k * 0x28, 0x28)
            if slot is None:
                continue
            pg = struct.unpack_from('<Q', slot, 0)[0]
            if pg in vptrs.values():
                off_, ln = struct.unpack_from('<II', slot, 8)
                ops = struct.unpack_from('<Q', slot, 0x10)[0]
                hits.append(dict(pi=scan_start + o, bufs=bufs, head=head, tail=tail,
                                 ring=ring, slot=k, off=off_, ln=ln, ops=ops,
                                 tmp=struct.unpack_from('<Q', region, o + P_TMP)[0]))
    print('pipes referencing our pages: %d' % len(hits))
    for h in hits:
        kind = 'spent' if h['ln'] == 0 else 'live'
        pi_alias = DMAP + (h['pi'] - MEMSTART)
        print('  %-5s pipe_inode_info=0x%x bufs=0x%x slot=%d (addr 0x%x) '
              'offset=%d len=%d ops=0x%x head=%d tail=%d ring=%d tmp=0x%x'
              % (kind, pi_alias, h['bufs'], h['slot'], h['bufs'] + h['slot'] * 0x28,
                 h['off'], h['ln'], h['ops'], h['head'], h['tail'], h['ring'], h['tmp']))
        nxt = h['head'] & (h['ring'] - 1)
        print('        next write slot = head&mask = %d -> plant at 0x%x'
              % (nxt, h['bufs'] + nxt * 0x28))
    return 0


if __name__ == '__main__':
    sys.exit(main())
