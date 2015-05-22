/* vi: set sw=4 ts=4: */
/*
 * close() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <unistd.h>

#include <bits/sclib.h>
#include <bits/sclib_syscalls.h>

int close(int fd)
{
	long ret = __internal_sys_close(fd);
	SCLIB_ERR_RET(ret);
	return ret;
}

#ifndef __LINUXTHREADS_OLD__
libc_hidden_def(close)
#else
libc_hidden_weak(close)
strong_alias(close,__libc_close)
#endif
