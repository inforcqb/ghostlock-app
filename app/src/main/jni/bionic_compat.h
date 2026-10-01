/*
 * bionic_compat.h -- build shim for the vendored AOSP system_properties sources.
 *
 * These sources are upstream AOSP files (see THIRD_PARTY_NOTICES.md) that are
 * normally compiled inside the platform build, where bionic's *private*
 * <sys/cdefs.h> provides a handful of internal helpers.  The NDK ships only the
 * public sysroot headers, so a few of those helpers are simply absent and the
 * build fails on them, e.g.:
 *
 *   system_properties/include/system_properties/prop_area.h:122:21:
 *     error: use of undeclared identifier '__BIONIC_ALIGN'
 *
 * This header is force-included by the `magica2jni` target in the root
 * Makefile (-include), so the vendored files stay byte-for-byte upstream and
 * the gap is documented in exactly one place.
 */
#ifndef GHOSTLOCK_BIONIC_COMPAT_H_
#define GHOSTLOCK_BIONIC_COMPAT_H_

/*
 * Round `__value` up to a multiple of `__alignment`.  Copied verbatim from
 * bionic/libc/include/sys/cdefs.h (same definition the platform build uses).
 * Only the arithmetic form makes sense at the two call sites, both of which
 * align a byte count: prop_area.h:122 and prop_area.cpp:161.
 */
#ifndef __BIONIC_ALIGN
#define __BIONIC_ALIGN(__value, __alignment) \
  (((__value) + (__alignment)-1) & ~((__alignment)-1))
#endif

#endif /* GHOSTLOCK_BIONIC_COMPAT_H_ */
