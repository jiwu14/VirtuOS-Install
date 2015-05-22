/* vi: set sw=4 ts=4: */
/*
 * readlink() for uClibc
 *
 * Copyright (C) 2000-2007 Erik Andersen <andersen@uclibc.org>
 * Copyright (C) 2012 Ruslan Nikolaev <rnikola@vt.edu>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <unistd.h>

#include <bits/sclib.h>

ssize_t readlink(const char *path, char *buf, size_t bufsize)
{
	char __abspath[PATH_MAX], *__dpath;
	long __ret;
	int __sysid;
	void *__rbuf, *__off;
	size_t __sz2;

	__dpath = sclib_get_path(__abspath, path, &__sysid, &__sz2);
	if (__sysid != SYSCALL_SYSID_LOCAL) {
		if (bufsize > PATH_MAX)
			bufsize = PATH_MAX;
		__rbuf = sclib_memory_alloc(&sclib_data[__sysid], bufsize + __sz2);
		SCLIB_MEM_RET(__rbuf, __ret);
		memcpy(__rbuf + bufsize, __dpath, __sz2);
		__off = sclib_mem(__sysid, __rbuf);
		__ret = SCLIB_REMOTE_CALL(__sysid, readlink, 3, __off + bufsize, __off, bufsize);
		if (!SCLIB_IS_ERR(__ret))
			memcpy(buf, __rbuf, __ret);
		sclib_memory_free(&sclib_data[__sysid], __rbuf);
	} else {
		__ret = SCLIB_LOCAL_CALL(readlink, 3, __dpath, buf, bufsize);
	}
error_mem:
	SCLIB_ERR_RET(__ret);
	return __ret;
}

libc_hidden_def(readlink)
