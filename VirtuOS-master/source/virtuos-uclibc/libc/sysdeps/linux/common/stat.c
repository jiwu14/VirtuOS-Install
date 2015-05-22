/* vi: set sw=4 ts=4: */
/*
 * stat() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 * Copyright (C) 2012 Ruslan Nikolaev <rnikola@vt.edu>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <unistd.h>
#include <sys/stat.h>
#include "xstatconv.h"

#include <bits/sclib.h>

int stat(const char *file_name, struct stat *buf)
{
	struct kernel_stat kbuf;
	char abspath[PATH_MAX], *dpath;
	long ret;
	int sysid;
	void *rbuf, *off;
	size_t sz;

    dpath = sclib_get_path(abspath, file_name, &sysid, &sz);
	if (sysid != SYSCALL_SYSID_LOCAL) {
		rbuf = sclib_memory_alloc(&sclib_data[sysid], sizeof(struct kernel_stat) + sz);
		SCLIB_MEM_RET(rbuf, ret);
		memcpy(rbuf + sizeof(struct kernel_stat), dpath, sz);
		off = sclib_mem(sysid, rbuf);
		ret = SCLIB_REMOTE_CALL(sysid, stat, 2, off + sizeof(struct kernel_stat), off);
		if (ret == 0)
			__xstat_conv(rbuf, buf);
		sclib_memory_free(&sclib_data[sysid], rbuf);
	} else {
		ret = SCLIB_LOCAL_CALL(stat, 2, dpath, &kbuf);
		if (ret == 0)
			__xstat_conv(&kbuf, buf);
	}
error_mem:
	SCLIB_ERR_RET(ret);
	return ret;
}
libc_hidden_def(stat)

#if ! defined __NR_stat64 && defined __UCLIBC_HAS_LFS__
strong_alias_untyped(stat,stat64)
libc_hidden_def(stat64)
#endif
