/* vi: set sw=4 ts=4: */
/*
 * uname() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 * Copyright (C) 2012 Ruslan Nikolaev <rnikola@vt.edu>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <sys/utsname.h>
#include <bits/sclib.h>

int uname(struct utsname *buf)
{
	struct utsname *rbuf;
	syscall_entry_t *pos;
	long ret, rret;

	rbuf = (struct utsname *) sclib_memory_alloc(&sclib_data[SYSCALL_SYSID_NETWORK], sizeof(struct utsname));
	SCLIB_MEM_RET(rbuf, ret);
	pos = SCLIB_REMOTE_CALL_ASYNC(SYSCALL_SYSID_NETWORK, uname, 1, sclib_mem(SYSCALL_SYSID_NETWORK, rbuf));
	ret = SCLIB_LOCAL_CALL(uname, 1, buf);
	rret = SCLIB_REMOTE_CALL_RESULT(SYSCALL_SYSID_NETWORK, uname, pos);
	if (SCLIB_IS_ERR(rret)) {
		ret = rret;
	} else {
		memcpy(buf->nodename, rbuf->nodename, sizeof(rbuf->nodename));
		memcpy(buf->domainname, rbuf->domainname, sizeof(rbuf->domainname));
	}
	sclib_memory_free(&sclib_data[SYSCALL_SYSID_NETWORK], rbuf);

error_mem:
	SCLIB_ERR_RET(ret);
	return ret;
}

libc_hidden_def(uname)
