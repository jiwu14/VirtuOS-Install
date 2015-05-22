/* vi: set sw=4 ts=4: */
/*
 * read() for uClibc
 *
 * Copyright (C) 2012 Ruslan Nikolaev <rnikola@vt.edu>
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>

#include <bits/sclib.h>
#include <bits/sclib_syscalls.h>

ssize_t read(int fd, void *buf, size_t count)
{
	ssize_t ret = __internal_sys_read(fd, buf, count);
	SCLIB_ERR_RET(ret);
	return ret;
}

#ifndef __LINUXTHREADS_OLD__
libc_hidden_def(read)
#else
libc_hidden_weak(read)
strong_alias(read,__libc_read)
#endif
