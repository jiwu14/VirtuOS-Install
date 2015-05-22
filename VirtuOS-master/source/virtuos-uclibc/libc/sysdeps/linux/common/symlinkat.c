/*
 * symlinkat() for uClibc
 *
 * Copyright (C) 2009 Analog Devices Inc.
 * Copyright (C) 2012-2013 Ruslan Nikolaev <rnikola@vt.edu>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <unistd.h>

#include <bits/sclib.h>

#ifdef __NR_symlinkat
int symlinkat(const char *from, int tofd, const char *to)
{
	const char *__dpath = (const char *) to, *__dlink;
	char __abspath[PATH_MAX];
	void *__rbuf = __rbuf, *__off;
	size_t __sz2, __sz1;
	int __sysid, __sysid1;
	long __ret, __dfd;
	if (tofd == AT_FDCWD) {
		__dpath = sclib_get_path(__abspath, __dpath ? __dpath : "", &__sysid, &__sz2);
		__dfd = -1;
	} else if (__dpath && *__dpath == '/') {
		__dpath = sclib_get_path(__abspath, __dpath, &__sysid, &__sz2);
		__dfd = -1;
	} else {
		__sz2 = __dpath ? (strlen(__dpath) + 1) : 0;
		__dfd = sclib_file_getid(&sclib_file, tofd, &__sysid);
		SCLIB_ERR_RET(__dfd);
	}
	__dlink = sclib_get_link(from, &__sysid1);
	if (__sysid1 != SYSCALL_SYSID_ALL && __sysid != __sysid1) {
		__ret = -EINVAL;
		goto error_mem;
	}
	if (__sysid != SYSCALL_SYSID_LOCAL) {
		__sz1 = strlen(__dlink) + 1;
		__off = NULL;
		if (__sz1 + __sz2 != 0) {
			__rbuf = sclib_memory_alloc(&sclib_data[__sysid], __sz1 + __sz2);
			SCLIB_MEM_RET(__rbuf, __ret);
			memcpy(mempcpy(__rbuf, __dlink, __sz1), __dpath, __sz2);
			__off = sclib_mem(__sysid, __rbuf);
		}
		__ret = SCLIB_REMOTE_CALL(__sysid, symlinkat, 3, __off, __dfd, __sz2 ? (__off + __sz1) : NULL);
		if (__sz1 + __sz2 != 0)
			sclib_memory_free(&sclib_data[__sysid], __rbuf);
	} else {
		__ret = SCLIB_LOCAL_CALL(symlinkat, 3, __dlink, __dfd, __dpath);
	}
error_mem:
	if (__dfd >= 0)
		sclib_file_put(&sclib_file, tofd);
	SCLIB_ERR_RET(__ret);
	return __ret;
}
#else
/* should add emulation with symlink() and /proc/self/fd/ ... */
#endif
