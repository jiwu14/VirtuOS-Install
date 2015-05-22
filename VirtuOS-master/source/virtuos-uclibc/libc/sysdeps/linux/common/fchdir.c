/* vi: set sw=4 ts=4: */
/*
 * fchdir() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 * Copyright (C) 2013 Ruslan Nikolaev <rnikola@vt.edu>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <unistd.h>

#include <bits/sclib.h>

int fchdir(int fd)
{
	long ret, dfd;
	int sysid;
	void *rbuf;

	dfd = sclib_file_getid(&sclib_file, fd, &sysid);
	SCLIB_ERR_RET(dfd);
	if (sysid != SYSCALL_SYSID_LOCAL) {
		rbuf = sclib_memory_alloc(&sclib_data[sysid], PATH_MAX - sizeof(SCLIB_STORAGE_PREFIX) + 1);
		SCLIB_MEM_RET(rbuf, ret);
		ret = SCLIB_REMOTE_CALL(sysid, syscall_service_fchdir, 3, dfd, sclib_mem(sysid, rbuf), PATH_MAX - sizeof(SCLIB_STORAGE_PREFIX) + 1);
		if (!SCLIB_IS_ERR(ret)) {
			memcpy(mempcpy(sclib_file.curdir, SCLIB_STORAGE_PREFIX, sizeof(SCLIB_STORAGE_PREFIX) - 1), rbuf, ret);
			ret += sizeof(SCLIB_STORAGE_PREFIX) - 1;
		}
		sclib_memory_free(&sclib_data[sysid], rbuf);
	} else {
		ret = SCLIB_LOCAL_CALL(syscall_service_fchdir, 3, dfd, sclib_file.curdir, PATH_MAX);
	}

error_mem:
	sclib_file_put(&sclib_file, fd);
	SCLIB_ERR_RET(ret);
	sclib_file.curdir_size = ret;
	return 0;
}

libc_hidden_def(fchdir)
