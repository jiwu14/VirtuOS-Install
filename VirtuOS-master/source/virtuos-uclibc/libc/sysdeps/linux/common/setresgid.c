/* vi: set sw=4 ts=4: */
/*
 * setresgid() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 * Copyright (C) 2012 Ruslan Nikolaev <rnikola@vt.edu>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#ifdef __USE_GNU
#include <unistd.h>

#include <bits/sclib.h>

#if defined(__NR_setresgid32)
# undef __NR_setresgid
# define __NR_setresgid __NR_setresgid32

_syscall3(int, setresgid, gid_t, rgid, gid_t, egid, gid_t, sgid)
libc_hidden_def(setresgid)

#elif defined(__NR_setresgid)

static __inline__ int __syscall_setresgid(__kernel_gid_t rgid,
	__kernel_gid_t egid, __kernel_gid_t sgid)
{
	long ret = SCLIB_ALL_SIMPLE_CALL(setresgid, 3, rgid, egid, sgid);
	SCLIB_ERR_RET(ret);
	return ret;
}

int setresgid(gid_t rgid, gid_t egid, gid_t sgid)
{
	if (((rgid + 1) > (gid_t) ((__kernel_gid_t) - 1U))
		|| ((egid + 1) > (gid_t) ((__kernel_gid_t) - 1U))
		|| ((sgid + 1) > (gid_t) ((__kernel_gid_t) - 1U))) {
		__set_errno(EINVAL);
		return -1;
	}
	return (__syscall_setresgid(rgid, egid, sgid));
}
libc_hidden_def(setresgid)

#endif

#endif
