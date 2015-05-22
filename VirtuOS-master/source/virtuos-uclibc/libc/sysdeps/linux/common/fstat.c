/* vi: set sw=4 ts=4: */
/*
 * fstat() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <unistd.h>
#include <sys/stat.h>
#include "xstatconv.h"

#include <bits/sclib.h>

int fstat(int fd, struct stat *buf)
{
	int sysid;
	long ret, dfd = sclib_file_getid(&sclib_file, fd, &sysid);

	SCLIB_ERR_RET(dfd);
	if (sysid != SYSCALL_SYSID_LOCAL) {
		void *mem = sclib_memory_alloc(&sclib_data[sysid], sizeof(struct kernel_stat));

		SCLIB_MEM_RET(mem, ret);
		ret = SCLIB_REMOTE_CALL(sysid, fstat, 2, dfd, sclib_mem(sysid, mem));
		if (!SCLIB_IS_ERR(ret))
			__xstat_conv(mem, buf);
		sclib_memory_free(&sclib_data[sysid], mem);
	} else {
		struct kernel_stat kbuf;
		ret = SCLIB_LOCAL_CALL(fstat, 2, dfd, &kbuf);
		if (!SCLIB_IS_ERR(ret))
			__xstat_conv(&kbuf, buf);
	}

error_mem:
	sclib_file_put(&sclib_file, fd);
	SCLIB_ERR_RET(ret);
	return 0;
}

libc_hidden_def(fstat)

#if ! defined __NR_fstat64 && defined __UCLIBC_HAS_LFS__
strong_alias_untyped(fstat,fstat64)
libc_hidden_def(fstat64)
#endif
