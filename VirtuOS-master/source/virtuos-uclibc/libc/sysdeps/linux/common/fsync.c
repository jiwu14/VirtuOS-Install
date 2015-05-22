/* vi: set sw=4 ts=4: */
/*
 * fsync() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 * Copyright (C) 2012 Ruslan Nikolaev <rnikola@vt.edu>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <unistd.h>

#include <bits/sclib.h>

#ifdef __UCLIBC_HAS_THREADS_NATIVE__
#include "sysdep-cancel.h"
#else
#define SINGLE_THREAD_P 1
#endif

static __always_inline
int __syscall_fsync(int fd)
{
	int sysid;
	long ret, dfd = sclib_file_getid(&sclib_file, fd, &sysid);

	SCLIB_ERR_RET(dfd);
	ret = SCLIB_SYSID_CALL(sysid, fsync, 1, dfd);
	sclib_file_put(&sclib_file, fd);
	SCLIB_ERR_RET(ret);
	return ret;
}

extern __typeof(fsync) __libc_fsync;

int __libc_fsync(int fd)
{
	if (SINGLE_THREAD_P)
		return __syscall_fsync(fd);

#ifdef __UCLIBC_HAS_THREADS_NATIVE__
	int oldtype = LIBC_CANCEL_ASYNC ();
	int result = __syscall_fsync(fd);
	LIBC_CANCEL_RESET (oldtype);
	return result;
#endif
}

weak_alias(__libc_fsync, fsync)
