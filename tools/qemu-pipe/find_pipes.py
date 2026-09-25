"""Find pipe_inode_info objects in a physical dump.

struct pipe_inode_info (this image):
  +0x60 head (u32), +0x64 tail (u32), +0x68 max_usage (u32), +0x6c ring_size (u32),
  +0xa8 bufs (struct pipe_buffer *), +0x90 tmp_page, +0xb0 nr_accounted...

Heuristic: ring_size in {1,2,4,8,16,32,64,128,256}, 0 < max_usage <= ring_size,
tail <= head <= ring_size, and bufs pointing into the kernel heap (0xffffffc0...).

Usage: find_pipes.py --chunk glram3.bin [--base 0x100000000] [--start 0x100000000]
                     [--len 0x2000000] [--page <phys of a known pipe page>]
"""
import struct
import sys

P_HEAD, P_TAIL, P_MAX, P_RING, P_BUFS, P_TMP = 0x60, 0x64, 0x68, 0x6c, 0xa8, 0x90
RINGS = (1, 2, 4, 8, 16, 32, 64, 128, 256)


def main():
    path, base, start, length = None, 0x40000000, None, 0x4000000
    page = None
    a = sys.argv[1:]
    i = 0
    while i < len(a):
        if a[i] == '--chunk':
            path = a[i + 1]; i += 2
        elif a[i] == '--base':
            base = int(a[i + 1], 0); i += 2
        elif a[i] == '--start':
            start = int(a[i + 1], 0); i += 2
        elif a[i] == '--len':
            length = int(a[i + 1], 0); i += 2
        elif a[i] == '--page':
            page = int(a[i + 1], 0); i += 2
        else:
            print('unknown arg', a[i]); return 2
    if start is None:
        start = base
    data = open(path, 'rb').read()
    off0 = start - base
    win = data[off0:off0 + length]
    print('scanning %s phys 0x%x..0x%x (%.1f MB)'
          % (path, start, start + len(win), len(win) / 1e6))

    page_ptr = None
    if page is not None:
        page_ptr = 0xfffffffe00000000 + ((page - 0x40000000) >> 12) * 0x40
        print('looking for page 0x%x -> struct page 0x%x' % (page, page_ptr))

    # kmalloc objects live in the linear map: alias = 0xffffff8000000000 +
    # (phys - memstart), so convert back to a phys offset to read the dump.
    DMAP = 0xffffff8000000000
    MEMSTART = 0x40000000

    def dmap_to_off(q):
        return (q - DMAP) + MEMSTART - base

    found = []
    for o in range(0, len(win) - 0xc0, 8):
        head, tail, mx, ring = struct.unpack_from('<IIII', win, o + P_HEAD)
        if ring not in RINGS or mx == 0 or mx > ring or tail > head or head > ring:
            continue
        bufs = struct.unpack_from('<Q', win, o + P_BUFS)[0]
        tmp = struct.unpack_from('<Q', win, o + P_TMP)[0]
        if not (DMAP <= bufs < DMAP + 0x100000000):
            continue
        scored = False
        detail = ''
        if page_ptr is not None:
            for k in range(ring):
                q = struct.unpack_from('<Q', data, dmap_to_off(bufs) + k * 0x28)[0]
                if q == page_ptr:
                    scored = True
                    detail += ' slot%d.page==our page%s' % (
                        k, '' if k == 0 else ' (slot %d!)' % k)
        found.append((start + o, head, tail, mx, ring, bufs, tmp, scored, detail))

    print('candidates: %d' % len(found))
    for (addr, head, tail, mx, ring, bufs, tmp, scored, detail) in found:
        print('  pipe_inode_info @0x%-11x head=%d tail=%d max_usage=%d ring=%d bufs=0x%x '
              'tmp_page=0x%x%s%s'
              % (addr, head, tail, mx, ring, bufs, tmp,
                 '  <== MATCH' if scored else '', detail))
    return 0


if __name__ == '__main__':
    sys.exit(main())
