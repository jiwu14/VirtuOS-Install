/*
 * fstatat() for uClibc
 *
 * Copyright (C) 2009 Analog Devices Inc.
 * Copyright (C) 2012 Ruslan Nikolaev <rnikola@vt.edu>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <sys/stat.h>
#include "xstatconv.h"

#include <bits/sclib.h>

/* 64bit ports tend to favor newfstatat() */
#ifdef __NR_newfstatat
# define __NR_fstatat64 __NR_newfstatat
#endif

#ifdef __NR_fstatat64
int fstatat(int fd, const char *file, struct stat *buf, int flag)
{
	int sysid;
	long ret, dfd;

	if (fd == AT_FDCWD) {
		sysid = SYSCALL_SYSID_LOCAL;
		dfd = fd; /* AT_FDCWD is negative */
	} else if (file && *file == '/') {
		sysid = SYSCALL_SYSID_LOCAL;
		dfd = -1;
	} else {
		dfd = sclib_file_getid(&sclib_file, fd, &sysid);
		SCLIB_ERR_RET(dfd);
	}

	if (sysid != SYSCALL_SYSID_LOCAL) {
		void *mem;
		if (unlikely(file && *file != '\0')) {
			ret = -EINVAL;
			goto error_path;
		}
		mem = sclib_memory_alloc(&sclib_data[sysid], sizeof(struct kernel_stat64));
		SCLIB_MEM_RET(mem, ret);
		ret = SCLIB_REMOTE_CALL(sysid, fstatat64, 4, dfd, -1, sclib_mem(sysid, mem), flag);
		if (!SCLIB_IS_ERR(ret))
			__xstat32_conv(mem, buf);
		sclib_memory_free(&sclib_data[sysid], mem);
	} else {
		struct kernel_stat64 kbuf;
		ret = SCLIB_LOCAL_CALL(fstatat64, 4, dfd, file, &kbuf, flag);
		if (!SCLIB_IS_ERR(ret))
			__xstat32_conv(&kbuf, buf);
	}

error_mem:
error_path:
	if (dfd >= 0)
		sclib_file_put(&sclib_file, fd);
	SCLIB_ERR_RET(ret);
	return 0;
}
#else
/* should add emulation with fstat() and /proc/self/fd/ ... */
#endif
