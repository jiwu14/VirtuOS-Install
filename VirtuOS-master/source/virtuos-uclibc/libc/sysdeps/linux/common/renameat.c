/*
 * renameat() for uClibc
 *
 * Copyright (C) 2009 Analog Devices Inc.
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <stdio.h>

#include <bits/sclib.h>

#ifdef __NR_renameat
int renameat(int oldfd, const char *old, int newfd, const char *new)
{
	return SCLIB_DFD_SYSCALL_AT2(renameat, 4, oldfd, old, newfd, new);
}
#else
/* should add emulation with rename() and /proc/self/fd/ ... */
#endif
