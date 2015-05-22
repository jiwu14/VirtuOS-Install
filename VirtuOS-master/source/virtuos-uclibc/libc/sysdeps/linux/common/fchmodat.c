/*
 * fchmodat() for uClibc
 *
 * Copyright (C) 2009 Analog Devices Inc.
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <sys/stat.h>

#include <bits/sclib.h>

#ifdef __NR_fchmodat

int fchmodat(int dirfd, const char *file, mode_t mode, int flags)
{
	return SCLIB_DFD_SYSCALL_AT(fchmodat, 4, dirfd, file, mode, flags);
}

#else
/* should add emulation with fchmod() and /proc/self/fd/ ... */
#endif
