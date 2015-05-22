/*
 * futimesat() for uClibc
 *
 * Copyright (C) 2009 Analog Devices Inc.
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <sys/time.h>

#include <bits/sclib.h>

#ifdef __NR_futimesat
int futimesat(int fd, const char *file, const struct timeval *tvp)
{
	return SCLIB_DFD_INBUF_SYSCALL_AT(futimesat, sizeof(struct timeval) * 2, 3, fd, file, tvp);
}
#else
/* should add emulation with futimes() and /proc/self/fd/ ... */
#endif
