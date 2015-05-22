/*
 * faccessat() for uClibc
 *
 * Copyright (C) 2009 Analog Devices Inc.
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <unistd.h>

#include <bits/sclib.h>

#ifdef __NR_faccessat
int faccessat(int fd, const char *file, int type, int flag)
{
	return SCLIB_DFD_SYSCALL_AT(faccessat, 4, fd, file, type, flag);
}
#else
/* should add emulation with faccess() and /proc/self/fd/ ... */
#endif
