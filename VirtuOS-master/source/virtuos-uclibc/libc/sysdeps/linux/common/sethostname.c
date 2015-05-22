/* vi: set sw=4 ts=4: */
/*
 * sethostname() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 * Copyright (C) 2012 Ruslan Nikolaev <rnikola@vt.edu>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <unistd.h>
#include <bits/sclib.h>

#if defined __USE_BSD || (defined __USE_XOPEN && !defined __USE_UNIX98)

int sethostname(const char *name, size_t len)
{
	void *mem;
	long ret;

	mem = sclib_memory_alloc(&sclib_data[SYSCALL_SYSID_NETWORK], len);
	SCLIB_MEM_RET(mem, ret);
	mem = memcpy(mem, name, len);
	ret = SCLIB_REMOTE_CALL(SYSCALL_SYSID_NETWORK, sethostname, 2, sclib_mem(SYSCALL_SYSID_NETWORK, mem), len);
	sclib_memory_free(&sclib_data[SYSCALL_SYSID_NETWORK], mem);

error_mem:
	SCLIB_ERR_RET(ret);
	return ret;
}

#endif
