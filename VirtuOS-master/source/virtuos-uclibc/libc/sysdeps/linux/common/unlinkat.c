/*
 * unlinkat() for uClibc
 *
 * Copyright (C) 2009 Analog Devices Inc.
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <unistd.h>

#include <bits/sclib.h>

#ifdef __NR_unlinkat
int unlinkat(int fd, const char *file, int flag)
{
	return SCLIB_DFD_SYSCALL_AT(unlinkat, 3, fd, file, flag);
}
#else
/* should add emulation with unlink() and /proc/self/fd/ ... */
#endif
