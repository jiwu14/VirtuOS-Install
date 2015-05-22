/* vi: set sw=4 ts=4: */
/*
 * symlink() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 * Copyright (C) 2012-2013 Ruslan Nikolaev <rnikola@vt.edu>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#if defined __USE_BSD || defined __USE_UNIX98 || defined __USE_XOPEN2K
#include <unistd.h>

#include <bits/sclib.h>

int symlink(const char *oldpath, const char *newpath)
{
	const char *__dlink;
	char __abspath[PATH_MAX], *__dpath;
	long __ret;
	int __sysid, __sysid2;
	void *__rbuf, *__off;
	size_t __sz2, __sz1;
	__dpath = sclib_get_path(__abspath, newpath, &__sysid, &__sz1);
	__dlink = sclib_get_link(oldpath, &__sysid2);
	if (__sysid2 != SYSCALL_SYSID_ALL && __sysid != __sysid2) {
		__ret = -EINVAL;
		goto error_mem;
	}
	if (__sysid != SYSCALL_SYSID_LOCAL) {
		__sz2 = strlen(__dlink) + 1;
		__rbuf = sclib_memory_alloc(&sclib_data[__sysid], __sz1 + __sz2);
		SCLIB_MEM_RET(__rbuf, __ret);
		memcpy(mempcpy(__rbuf, __dpath, __sz1), __dlink, __sz2);
		__off = sclib_mem(__sysid, __rbuf);
		__ret = SCLIB_REMOTE_CALL(__sysid, symlink, 2, __off + __sz1, __off);
		sclib_memory_free(&sclib_data[__sysid], __rbuf);
	} else {
		__ret = SCLIB_LOCAL_CALL(symlink, 2, __dlink, __dpath);
	}
error_mem:
	SCLIB_ERR_RET(__ret);
	return __ret;
}
#endif
