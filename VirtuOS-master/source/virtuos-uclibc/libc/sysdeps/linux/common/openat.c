/*
 * openat() for uClibc
 *
 * Copyright (C) 2009 Analog Devices Inc.
 * Copyright (C) 2012-2013 Ruslan Nikolaev <rnikola@vt.edu>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#define openat __xx_openat
#include <sys/syscall.h>
#include <fcntl.h>
#undef openat

#include <bits/sclib.h>

#ifdef __NR_openat
/* The openat() prototype is varargs based, but we don't care about that
 * here, so need to provide our own dedicated signature.
 */
extern int openat(int fd, const char *file, int oflag, mode_t mode);
libc_hidden_proto(openat)

int openat(int dirfd, const char *file, int oflag, mode_t mode)
{
	long ldirfd, lfd, fd;

	if (dirfd == AT_FDCWD) {
		ldirfd = dirfd; /* AT_FDCWD is negative */
	} else if (file && *file == '/') {
		ldirfd = -1;
	} else {
		ldirfd = sclib_file_get(&sclib_file, dirfd, SYSCALL_SYSID_LOCAL);
		SCLIB_ERR_RET(ldirfd);
	}
	fd = sclib_file_add(&sclib_file, 0);
	if (SCLIB_IS_ERR(fd)) {
		lfd = fd;
		goto fd_error;
	}
	lfd = SCLIB_LOCAL_CALL(openat, 4, ldirfd, file, oflag, mode);
	if (SCLIB_IS_ERR(lfd)) {
		sclib_file_add_fail(&sclib_file, fd);
	} else {
		uint8_t lfd_flags = 0;
		if (oflag & O_CLOEXEC)
			lfd_flags |= SCLIB_FD_EXEC;
		sclib_file_add_ok(&sclib_file, fd, lfd, SYSCALL_SYSID_LOCAL, lfd_flags, 0);
	}
fd_error:
	if (ldirfd >= 0)
		sclib_file_put(&sclib_file, dirfd);
	SCLIB_ERR_RET(lfd);
	return fd;
}
libc_hidden_def(openat)
#else
/* should add emulation with open() and /proc/self/fd/ ... */
#endif
