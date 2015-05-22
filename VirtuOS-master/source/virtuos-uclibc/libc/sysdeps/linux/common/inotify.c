/* vi: set sw=4 ts=4: */
/*
 * inotify interface for uClibc
 *
 * Copyright (C) 2006 Austin Morgan <admorgan@morgancomputers.net>
 * Copyright (C) 2006 by Erik Andersen <andersen@codepoet.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <sys/inotify.h>

#include <bits/sclib.h>

#ifdef __NR_inotify_init
int inotify_init(void)
{
	long lfd, fd = sclib_file_add(&sclib_file, 0);

	SCLIB_ERR_RET(fd);
	lfd = SCLIB_LOCAL_CALL(inotify_init, 0);
	sclib_file_add_done(&sclib_file, fd, lfd, SYSCALL_SYSID_LOCAL, 0, 0);
	SCLIB_ERR_RET(lfd);
	return fd;
}
#endif

#ifdef __NR_inotify_init1
int inotify_init1(int flags)
{
	long lfd, fd = sclib_file_add(&sclib_file, 0);

	SCLIB_ERR_RET(fd);
	lfd = SCLIB_LOCAL_CALL(inotify_init1, 1, flags);
	if (SCLIB_IS_ERR(lfd)) {
		sclib_file_add_fail(&sclib_file, fd);
		fd = lfd;
	} else {
		uint8_t lfd_flags = 0;
		if (flags & IN_CLOEXEC)
			lfd_flags |= SCLIB_FD_EXEC;
		sclib_file_add_ok(&sclib_file, fd, lfd, SYSCALL_SYSID_LOCAL, lfd_flags, 0);
	}
	SCLIB_ERR_RET(lfd);
	return fd;
}
#endif

#ifdef __NR_inotify_add_watch
int inotify_add_watch(int fd, const char * path, uint32_t mask)
{
	return SCLIB_LFDPATH_SYSCALL(inotify_add_watch, 3, fd, path, mask);
}
#endif

#ifdef __NR_inotify_rm_watch
int inotify_rm_watch(int fd, uint32_t wd)
{
	return SCLIB_LFD_SYSCALL(inotify_rm_watch, 2, fd, wd);
}
#endif
