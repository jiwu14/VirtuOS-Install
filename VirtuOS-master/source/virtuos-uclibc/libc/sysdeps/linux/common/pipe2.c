/* vi: set sw=4 ts=4: */
/*
 * pipe2() for uClibc
 *
 * Copyright (C) 2011 Bernhard Reutner-Fischer <uclibc@uclibc.org>
 * Copyright (C) 2012 Ruslan Nikolaev <rnikola@vt.edu>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <unistd.h>

#include <bits/sclib.h>

#ifdef __NR_pipe2

int pipe2(int *fd, int flags)
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
	ret = SCLIB_LOCAL_CALL(pipe2, 2, lfd, flags);
	if (SCLIB_IS_ERR(ret)) {
		sclib_file_add_fail(&sclib_file, fd[1]);
	} else {
		uint8_t lfd_flags = 0;
		if (flags & O_CLOEXEC)
			lfd_flags |= SCLIB_FD_EXEC;
		sclib_file_add_ok(&sclib_file, fd[1], lfd[1], SYSCALL_SYSID_LOCAL, lfd_flags, 0);
	}
lfd_err1:
	if (SCLIB_IS_ERR(ret)) {
		sclib_file_add_fail(&sclib_file, fd[0]);
	} else {
		uint8_t lfd_flags = 0;
		if (flags & O_CLOEXEC)
			lfd_flags |= SCLIB_FD_EXEC;
		sclib_file_add_ok(&sclib_file, fd[0], lfd[0], SYSCALL_SYSID_LOCAL, lfd_flags, 0);
	}
lfd_err2:
	SCLIB_ERR_RET(ret);
	return ret;
}

libc_hidden_def(pipe2)
#endif
