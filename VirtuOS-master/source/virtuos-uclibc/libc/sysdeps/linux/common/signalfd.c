/* vi: set sw=4 ts=4: */
/*
 * signalfd() for uClibc
 *
 * Copyright (C) 2008 Bernhard Reutner-Fischer <uclibc@uclibc.org>
 * Copyright (C) 2012 Ruslan Nikolaev <rnikola@vt.edu>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <signal.h>
#include <sys/signalfd.h>

#include <bits/sclib.h>

#if defined __NR_signalfd4
static __inline__ int __syscall_signalfd4(long fd, const sigset_t *mask, size_t sizemask, int flags)
{
	long lfd;

	if (fd == -1) {
		fd = sclib_file_add(&sclib_file, 0);
		SCLIB_ERR_RET(fd);
		lfd = SCLIB_LOCAL_CALL(signalfd, 4, -1, mask, sizemask, flags);
		if (SCLIB_IS_ERR(lfd)) {
			sclib_file_add_fail(&sclib_file, fd);
		} else {
			uint8_t lfd_flags = 0;
			if (flags & SFD_CLOEXEC)
				lfd_flags |= SCLIB_FD_EXEC;
			sclib_file_add_ok(&sclib_file, fd, lfd, SYSCALL_SYSID_LOCAL, lfd_flags, 0);
		}
	} else {
		lfd = sclib_file_get(&sclib_file, fd, SYSCALL_SYSID_LOCAL);
		SCLIB_ERR_RET(lfd);
		sclib_write_lock_fd_flags(&sclib_file, fd);
		lfd = SCLIB_LOCAL_CALL(signalfd, 4, lfd, mask, sizemask, flags);
		if (!SCLIB_IS_ERR(lfd)) {
			if (flags & SFD_CLOEXEC)
				sclib_file.fds[fd].flags |= SCLIB_FD_EXEC;
			else
				sclib_file.fds[fd].flags &= ~SCLIB_FD_EXEC;
		}
		sclib_write_unlock_fd_flags(&sclib_file, fd);
		sclib_file_put(&sclib_file, fd);
	}
	SCLIB_ERR_RET(lfd);
	return fd;
}
#elif defined __NR_signalfd
static __inline__ int __syscall_signalfd(long fd, const sigset_t *mask, size_t sizemask)
{
	long dfd;

	if (fd == -1) {
		fd = sclib_file_add(&sclib_file, 0);
		SCLIB_ERR_RET(fd);
		lfd = SCLIB_LOCAL_CALL(signalfd, 3, -1, mask, sizemask);
		sclib_file_add_done(&sclib_file, fd, lfd, SYSCALL_SYSID_LOCAL, 0, 0);
	} else {
		lfd = sclib_file_get(&sclib_file, fd, SYSCALL_SYSID_LOCAL);
		SCLIB_ERR_RET(lfd);
		lfd = SCLIB_LOCAL_CALL(signalfd, 3, lfd, mask, sizemask);
		sclib_file_put(&sclib_file, fd);
	}
	SCLIB_ERR_RET(lfd);
	return fd;
}
#endif

#if defined __NR_signalfd4 || defined __NR_signalfd
int signalfd (int fd, const sigset_t *mask, int flags)
{
#if defined __NR_signalfd4
	return __syscall_signalfd4(fd, mask, _NSIG / 8, flags);
#elif defined __NR_signalfd
	if (flags != 0) {
		__set_errno(EINVAL);
		return -1;
	}
	return __syscall_signalfd(fd, mask, _NSIG / 8);
#endif
}
#endif
