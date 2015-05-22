/* vi: set sw=4 ts=4: */
/*
 * eventfd() for uClibc
 *
 * Copyright (C) 2011 Jean-Christian de Rivaz <jc@eclis.ch>
 * Copyright (C) 2012 Ruslan Nikolaev <rnikola@vt.edu>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <sys/eventfd.h>

#include <bits/sclib.h>

/*
 * eventfd()
 */
#ifdef __NR_eventfd
int eventfd(int count, int flags)
{
	long lfd, fd = sclib_file_add(&sclib_file, 0);

	SCLIB_ERR_RET(fd);
	flags = 0; /* Not used for eventfd, only for eventfd2 */
	lfd = SCLIB_LOCAL_CALL(eventfd, 2, count, flags);
	sclib_file_add_done(&sclib_file, fd, lfd, SYSCALL_SYSID_LOCAL, 0, 0);
	SCLIB_ERR_RET(lfd);
	return fd;
}
#endif
