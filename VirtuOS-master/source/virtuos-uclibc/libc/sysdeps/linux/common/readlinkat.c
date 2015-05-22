/*
 * readlinkat() for uClibc
 *
 * Copyright (C) 2009 Analog Devices Inc.
 * Copyright (C) 2012-2013 Ruslan Nikolaev <rnikola@vt.edu>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <unistd.h>

#include <bits/sclib.h>

#ifdef __NR_readlinkat
ssize_t readlinkat(int fd, const char *path, char *buf, size_t bufsize)
{
	const char *__dpath = (const char *) path;
	char __abspath[PATH_MAX];
	void *__rbuf = __rbuf, *__off;
	size_t __sz2;
	int __sysid;
	long __ret, __dfd;
	
	if (fd == AT_FDCWD) {
		__dpath = sclib_get_path(__abspath, __dpath ? __dpath : "", &__sysid, &__sz2);
		__dfd = -1;
	} else if (__dpath && *__dpath == '/') {
		__dpath = sclib_get_path(__abspath, __dpath, &__sysid, &__sz2);
		__dfd = -1;
	} else {
		__sz2 = __dpath ? (strlen(__dpath) + 1) : 0;
		__dfd = sclib_file_getid(&sclib_file, fd, &__sysid);
		SCLIB_ERR_RET(__dfd);
	}
	if (__sysid != SYSCALL_SYSID_LOCAL) {
		if (bufsize > PATH_MAX)
			bufsize = PATH_MAX;
		__rbuf = sclib_memory_alloc(&sclib_data[__sysid], bufsize + __sz2);
		SCLIB_MEM_RET(__rbuf, __ret);
		memcpy(__rbuf + bufsize, __dpath, __sz2);
		__off = sclib_mem(__sysid, __rbuf);
		__ret = SCLIB_REMOTE_CALL(__sysid, readlinkat, 4, __dfd, __sz2 ? (__off + bufsize) : NULL, __off, bufsize);
		if (!SCLIB_IS_ERR(__ret))
			memcpy(buf, __rbuf, __ret);
		sclib_memory_free(&sclib_data[__sysid], __rbuf);
	} else {
		__ret = SCLIB_LOCAL_CALL(readlinkat, 4, __dfd, __dpath, buf, bufsize);
	}
error_mem:
	if (__dfd >= 0)
		sclib_file_put(&sclib_file, fd);
	SCLIB_ERR_RET(__ret);
	return __ret;
}
#else
/* should add emulation with readlink() and /proc/self/fd/ ... */
#endif
