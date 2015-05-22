/* vi: set sw=4 ts=4: */
/*
 * chdir() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 * Copyright (C) 2013 Ruslan Nikolaev <rnikola@vt.edu>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <string.h>
#include <unistd.h>
#include <sys/param.h>

#include <bits/sclib.h>

int chdir(const char *path)
{
	char abspath[PATH_MAX];
	char *dpath;
	long ret;
	int sysid;
	void *rbuf, *off;
	size_t sz;

	dpath = sclib_get_path(abspath, path, &sysid, &sz);
	if (sysid != SYSCALL_SYSID_LOCAL) {
		rbuf = sclib_memory_alloc(&sclib_data[sysid], PATH_MAX);
		SCLIB_MEM_RET(rbuf, ret);
		rbuf = memcpy(rbuf, dpath, sz);
		off = sclib_mem(sysid, rbuf);
		ret = SCLIB_REMOTE_CALL(sysid, syscall_service_chdir, 3, off, off, PATH_MAX - sizeof(SCLIB_STORAGE_PREFIX) + 1);
		if (!SCLIB_IS_ERR(ret)) {
			memcpy(mempcpy(sclib_file.curdir, SCLIB_STORAGE_PREFIX, sizeof(SCLIB_STORAGE_PREFIX) - 1), rbuf, ret);
			ret += sizeof(SCLIB_STORAGE_PREFIX) - 1;
		}
		sclib_memory_free(&sclib_data[sysid], rbuf);
	} else {
		ret = SCLIB_LOCAL_CALL(syscall_service_chdir, 3, dpath, sclib_file.curdir, PATH_MAX);
	}

error_mem:
	SCLIB_ERR_RET(ret);
	sclib_file.curdir_size = ret;
	return 0;
}
libc_hidden_def(chdir)
