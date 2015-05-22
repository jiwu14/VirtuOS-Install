/* vi: set sw=4 ts=4: */
/*
 * utimes() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <utime.h>
#include <sys/time.h>

#include <bits/sclib.h>

#ifdef __NR_utimes
int utimes(const char *file, const struct timeval *tvp)
{
	return SCLIB_PATH_INBUF_CALL(utimes, sizeof(struct timeval) * 2, 2, file, tvp);
}
#else
#include <stdlib.h>


int utimes(const char *file, const struct timeval tvp[2])
{
	struct utimbuf buf, *times;

	if (tvp) {
		times = &buf;
		times->actime = tvp[0].tv_sec;
		times->modtime = tvp[1].tv_sec;
	} else {
		times = NULL;
	}
	return utime(file, times);
}
#endif
libc_hidden_def(utimes)
