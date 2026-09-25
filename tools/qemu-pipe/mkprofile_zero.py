"""Patch kernel_phys_load in a GLK1 profile and repack the guest initramfs.

GLK1 layout (see src/core/profile_binary.cpp):
  header 12B: 'GLK1' | ver u16@4 | route u8@6 | kernel_major u8@7 |
              shizuku u8@8 | fallback u8@9 | release_len u16@10
  release_len bytes of uname_r, then 86 * 8-byte LE fields.

Field order (0-based): the first 15 are task_struct, 16..30 cred, 31..41 off_*,
then 42 mcast_waiter_off ... 51 kernel_phys_load (index 50), 52 pselect_shift ...

Usage: mkprofile_zero.py <in_profile> <out_profile> <hex_kernel_phys_load>
       mkinitrd.py    <out.cpio> <profile.bin> <bin_name>=<bin_path>
"""
import sys
from pathlib import Path

FIELDS = ['task_prio', 'task_normal_prio', 'task_sched_task_group', 'task_pi_lock',
          'task_pi_waiters', 'task_pi_top_task', 'task_pi_blocked_on', 'task_pid', 'task_tgid',
          'task_atomic_flags', 'task_real_cred', 'task_cred', 'task_comm', 'task_tasks',
          'task_seccomp', 'cred_copy_size', 'cred_usage_offset', 'cred_usage_value',
          'cred_caps_offset', 'cred_caps_count', 'cred_caps_value', 'cred_ref_count',
          'cred_ref0_offset', 'cred_ref1_offset', 'cred_ref2_offset', 'cred_ref3_offset',
          'cred_ref0_image', 'cred_ref1_image', 'cred_ref2_image', 'cred_ref3_image',
          'off_init_task', 'off_init_cred', 'off_empty_zero_page', 'off_mcast_fake_bss',
          'off_root_task_group', 'off_selinux_enforcing', 'off_selinux_blob_sizes',
          'off_security_hook_heads', 'off_slide_nfulnl_logger', 'off_slide_loggers_0_1',
          'off_slide_boot_id', 'mcast_waiter_off', 'mcast_buffer_size', 'mcast_task_offset',
          'mcast_lock_offset', 'mcast_fake_lock_offset', 'mcast_fake_task_offset',
          'mcast_lock_slots_offset', 'mcast_lock_slot_count', 'mcast_lock_slot_stride',
          'kernel_phys_load', 'pselect_waiter_shift', 'compact_waiter',
          'kernelsnitch_collisions', 'mm_struct_sz']


def patch(src, dst, phys_load):
    b = bytearray(Path(src).read_bytes())
    assert b[0:4] == b'GLK1', 'not a GLK1 profile'
    rel = int.from_bytes(b[10:12], 'little')
    base = 12 + rel
    i = FIELDS.index('kernel_phys_load')
    off = base + 8 * i
    old = int.from_bytes(b[off:off + 8], 'little')
    b[off:off + 8] = phys_load.to_bytes(8, 'little')
    Path(dst).write_bytes(bytes(b))
    print('  %s: kernel_phys_load 0x%x -> 0x%x' % (Path(dst).name, old, phys_load))


def rec(name, data, mode, ino):
    nb = name.encode() + b'\0'
    hdr = b'070701' + b''.join(b'%08X' % v for v in (
        ino, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(nb), 0))
    out = hdr + nb
    out += b'\0' * ((-len(out)) % 4)
    out += data
    out += b'\0' * ((-len(data)) % 4)
    return out


def pack(out_path, init, profile, bins):
    entries = [('init', Path(init).read_bytes(), 0o100755),
               ('profile-qemu.bin', Path(profile).read_bytes(), 0o100644)]
    names = []
    for name, path in bins:
        entries.append(('b-' + name, Path(path).read_bytes(), 0o100755))
        names.append(name)
    entries.append(('b-all', ('\n'.join(names) + '\n').encode(), 0o100644))
    blobs, ino = [], 1
    for name, data, mode in entries:
        blobs.append(rec(name, data, mode, ino))
        ino += 1
    blobs.append(rec('TRAILER!!!', b'', 0, 0))
    Path(out_path).write_bytes(b''.join(blobs))
    print('  wrote %s (%.2f MB) pick=%s' % (out_path, Path(out_path).stat().st_size / 1e6,
                                            names[0] if names else '-'))


if __name__ == '__main__':
    D = Path(r'C:\Users\ASUS\dsh\.scratch\qemu-gl')
    if sys.argv[1] == 'all':
        patch(D / 'profile-qemu.bin', D / 'profile-zero.bin', 0x40200000)
        pack(D / 'initramfs-zero.cpio', D / 'init', D / 'profile-zero.bin',
             [('local', str(D / 'ghostlock-local'))])
    else:
        patch(sys.argv[1], sys.argv[2], int(sys.argv[3], 0))
