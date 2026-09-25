"""Locate the daemon's primitive pipe (bufs + pipe_inode_info) in a physical RAM
dump, anchored on the real anon page the daemon wrote into.

Chain:
  1. find the pipe buffer page by content ("GLPRIMBUF" / "ISOLATE!" / "GLPIPEBUF")
     -> phys P
  2. vmemmap pointer of that page: V = VMEMMAP + ((P - MEMSTART) >> 12) * 0x40
  3. scan RAM for the 8-byte value V -> candidate pipe_buffer.page words
  4. validate the surrounding struct pipe_buffer {page, offset, len, ops, flags,
     private} and then scan for the bufs pointer -> pipe_inode_info
     {head@0x60, tail@0x64, max_usage@0x68, ring_size@0x6c, bufs@0xa8}

Usage:
  scan_pipe.py --chunk glram0.bin --chunk glram1.bin ... [--base 0x40000000]
               [--chunksize 0x40000000] [--vmemmap 0xfffffffe00000000]
               [--memstart 0x40000000] [--ops 0x...]
"""
import struct
import sys

PAGE = 0x1000
SPS = 0x40
PIPE_BUF_SZ = 0x28
P_HEAD, P_TAIL, P_MAX_USAGE, P_RING_SIZE, P_BUFS = 0x60, 0x64, 0x68, 0x6c, 0xa8
DIRECT_MAP = 0xffffff8000000000


class Dump:
    def __init__(self, paths, base, chunksize):
        self.parts = []
        phys = base
        for p in paths:
            self.parts.append((phys, open(p, 'rb').read()))
            phys += chunksize

    def total(self):
        return sum(len(d) for _, d in self.parts)

    def read(self, phys, n):
        for base, data in self.parts:
            if base <= phys < base + len(data) and phys + n <= base + len(data):
                off = phys - base
                return data[off:off + n]
        return None

    def find(self, needle, limit=200):
        out = []
        for base, data in self.parts:
            start = 0
            while True:
                i = data.find(needle, start)
                if i < 0:
                    break
                out.append(base + i)
                if len(out) >= limit:
                    return out
                start = i + 1
        return out


def u32(d, off):
    return struct.unpack_from('<I', d, off)[0]


def u64(d, off):
    return struct.unpack_from('<Q', d, off)[0]


def main():
    paths, base, chunksize = [], 0x40000000, 0x40000000
    vmemmap, memstart, ops = 0xfffffffe00000000, 0x40000000, None
    a = sys.argv[1:]
    i = 0
    while i < len(a):
        if a[i] == '--chunk':
            paths.append(a[i + 1]); i += 2
        elif a[i] == '--base':
            base = int(a[i + 1], 0); i += 2
        elif a[i] == '--chunksize':
            chunksize = int(a[i + 1], 0); i += 2
        elif a[i] == '--vmemmap':
            vmemmap = int(a[i + 1], 0); i += 2
        elif a[i] == '--memstart':
            memstart = int(a[i + 1], 0); i += 2
        elif a[i] == '--ops':
            ops = int(a[i + 1], 0); i += 2
        else:
            print('unknown arg', a[i]); return 2
    d = Dump(paths, base, chunksize)
    print('dump: %d chunks, %.2f GB, phys 0x%x..0x%x'
          % (len(paths), d.total() / 1e9, base, base + d.total()))

    anchors = []
    for sig in (b'GLPRIMBUF', b'ISOLATE!', b'GLPIPEBUF'):
        hits = d.find(sig, limit=6)
        for phys in hits:
            page = phys & ~(PAGE - 1)
            anchors.append((sig.decode(), page, phys - page))
            print('  %-9s @phys 0x%x  page 0x%x  in-page 0x%x'
                  % (sig.decode(), phys, page, phys - page))
    if not anchors:
        print('!! no pipe-buffer signature found -- daemon buffer not resident?')

    seen = set()
    for name, page, inpage in anchors:
        if page in seen:
            continue
        seen.add(page)
        pfn = (page - memstart) >> 12
        v = vmemmap + pfn * SPS
        alias = DIRECT_MAP + (page - memstart)
        print('\n== %s page  phys=0x%x alias=0x%x struct_page=v=0x%x pfn=0x%x =='
              % (name, page, alias, v, pfn))
        ptr_hits = d.find(struct.pack('<Q', v), limit=64)
        print('   occurrences of v in RAM: %d' % len(ptr_hits))
        for h in ptr_hits:
            win = d.read(h - 8, 0x40)
            if win is None:
                continue
            off_, ln = u32(win, 8 + 8), u32(win, 8 + 0xc)
            op = u64(win, 8 + 0x10)
            fl, priv = u32(win, 8 + 0x18), u64(win, 8 + 0x20)
            ok_ops = (ops is None) or (op == ops)
            tag = 'PIPE_BUFFER' if (ln <= 0x100000 and fl <= 0x40 and ok_ops) else 'other'
            print('   @phys 0x%-12x %-11s offset=0x%-6x len=0x%-8x ops=0x%x flags=0x%x priv=0x%x'
                  % (h, tag, off_, ln, op, fl, priv))
            if tag != 'PIPE_BUFFER':
                continue
            bufs_addr = h
            for j in d.find(struct.pack('<Q', bufs_addr), limit=16):
                pi = d.read(j - P_BUFS, 0xc0)
                if pi is None:
                    continue
                head, tail = u32(pi, P_BUFS + P_HEAD - P_BUFS + 0) if False else (u32(pi, P_HEAD), u32(pi, P_TAIL))
                mu, ring = u32(pi, P_MAX_USAGE), u32(pi, P_RING_SIZE)
                if u64(pi, P_BUFS) != bufs_addr:
                    continue
                sane = ring in (1, 2, 4, 8, 16, 32, 64, 128, 256) and tail <= head <= ring
                print('   -> pipe_inode_info cand @0x%x head=0x%x tail=0x%x max_usage=0x%x '
                      'ring=0x%x sane=%s' % (j - P_BUFS, head, tail, mu, ring, sane))
    return 0


if __name__ == '__main__':
    sys.exit(main())
