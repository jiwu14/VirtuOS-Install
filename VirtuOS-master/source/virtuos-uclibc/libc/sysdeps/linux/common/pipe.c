/* vi: set sw=4 ts=4: */
/*
 * pipe() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 * Copyright (C) 2012 Ruslan Nikolaev <rnikola@vt.edu>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <unistd.h>

#include <bits/sclib.h>

int pipe(int *fd)
{
	long ret;
	int lfd[2];

	ret = sclib_file_add(&sclib_file, 0);
	if (SCLIB_IS_ERR(ret))
		goto lfd_err2;
	fd[0] = ret;
	ret = sclib_file_add(&sclib_file, 0);
	if (SCLIB_IS_ERR(ret))
		goto lfd_err1;
	fd[1] = ret;
	ret = SCLIB_LOCAL_CALL(pipe, 1, lfd);
	if (SCLIB_IS_ERR(ret)) {
		sclib_file_add_fail(&sclib_file, fd[1]);
	} else {
		sclib_file_add_ok(&sclib_file, fd[1], lfd[1], SYSCALL_SYSID_LOCAL, 0, 0);
	}
lfd_err1:
	if (SCLIB_IS_ERR(ret)) {
		sclib_file_add_fail(&sclib_file, fd[0]);
	} else {
		sclib_file_add_ok(&sclib_file, fd[0], lfd[0], SYSCALL_SYSID_LOCAL, 0, 0);
	}
lfd_err2:
	SCLIB_ERR_RET(ret);
	return ret;
}

libc_hidden_def(pipe)
