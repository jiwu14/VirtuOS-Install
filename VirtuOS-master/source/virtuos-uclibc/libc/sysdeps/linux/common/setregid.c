/* vi: set sw=4 ts=4: */
/*
 * setregid() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 * Copyright (C) 2012 Ruslan Nikolaev <rnikola@vt.edu>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <unistd.h>
#include <bits/wordsize.h>
#include <bits/sclib.h>

#if (__WORDSIZE == 32 && defined(__NR_setregid32)) || __WORDSIZE == 64
# ifdef __NR_setregid32
#  undef __NR_setregid
#  define __NR_setregid __NR_setregid32
# endif

int setregid(gid_t rgid, gid_t egid)
{
	long ret = SCLIB_ALL_SIMPLE_CALL(setregid, 2, rgid, egid);
	SCLIB_ERR_RET(ret);
	return ret;
}

#else

# define __NR___syscall_setregid __NR_setregid
static __inline__ _syscall2(int, __syscall_setregid,
		__kernel_gid_t, rgid, __kernel_gid_t, egid)

int setregid(gid_t rgid, gid_t egid)
{
	if (((rgid + 1) > (gid_t) ((__kernel_gid_t) - 1U))
		|| ((egid + 1) > (gid_t) ((__kernel_gid_t) - 1U))) {
		__set_errno(EINVAL);
		return -1;
	}
	return (__syscall_setregid(rgid, egid));
}
#endif

libc_hidden_def(setregid)
