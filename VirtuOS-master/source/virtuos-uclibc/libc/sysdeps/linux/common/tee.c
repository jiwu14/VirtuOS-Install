/* vi: set sw=4 ts=4: */
/*
 * tee() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <fcntl.h>

#include <bits/sclib.h>

#ifdef __NR_tee
ssize_t tee(int fdin, int fdout, size_t len, unsigned int flags)
{
	return SCLIB_LFD_SYSCALL2(tee, 4, fdin, fdout, len, flags);
}
#endif
