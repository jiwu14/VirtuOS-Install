/* vi: set sw=4 ts=4: */
/*
 * vmsplice() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 * Copyright (C) 2012 Ruslan Nikolaev <rnikola@vt.edu>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <fcntl.h>

#include <bits/sclib.h>

#ifdef __NR_vmsplice
ssize_t vmsplice(int fd, const struct iovec *iov, size_t count, unsigned int flags)
{
	return SCLIB_LFD_SYSCALL(vmsplice, 4, fd, iov, count, flags);
}
#endif
