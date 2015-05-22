/*
 * fchownat() for uClibc
 *
 * Copyright (C) 2009 Analog Devices Inc.
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <unistd.h>

#include <bits/sclib.h>

#ifdef __NR_fchownat
int fchownat(int fd, const char *file, uid_t owner, gid_t group, int flag)
{
	return SCLIB_DFD_SYSCALL_AT(fchownat, 5, fd, file, owner, group, flag);
}
#else
/* should add emulation with fchown() and /proc/self/fd/ ... */
#endif
