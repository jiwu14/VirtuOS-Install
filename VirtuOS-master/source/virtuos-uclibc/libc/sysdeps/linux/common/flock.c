/* vi: set sw=4 ts=4: */
/*
 * flock() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 * Copyright (C) 2012 Ruslan Nikolaev <rnikola@vt.edu>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <sys/file.h>

#include <bits/sclib.h>

static __inline__
int __syscall_flock(int fd, int operation)
{
	int sysid;
	long err, dfd = sclib_file_getid(&sclib_file, fd, &sysid);

	SCLIB_ERR_RET(dfd);
	err = SCLIB_SYSID_CALL(sysid, flock, 2, dfd, operation);
	sclib_file_put(&sclib_file, fd);
	SCLIB_ERR_RET(err);
	return err;
}

int flock(int fd, int operation)
{
	return (__syscall_flock(fd, operation));
}
