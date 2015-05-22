/* vi: set sw=4 ts=4: */
/*
 * setreuid() for uClibc
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

#if (__WORDSIZE == 32 && defined(__NR_setreuid32)) || __WORDSIZE == 64
# ifdef __NR_setreuid32
#  undef __NR_setreuid
#  define __NR_setreuid __NR_setreuid32
# endif

int setreuid(uid_t ruid, uid_t euid)
{
	long ret = SCLIB_ALL_SIMPLE_CALL(setreuid, 2, ruid, euid);
	SCLIB_ERR_RET(ret);
	return ret;
}

#else

# define __NR___syscall_setreuid __NR_setreuid
static __inline__ _syscall2(int, __syscall_setreuid,
		__kernel_uid_t, ruid, __kernel_uid_t, euid)

int setreuid(uid_t ruid, uid_t euid)
{
	if (((ruid + 1) > (uid_t) ((__kernel_uid_t) - 1U))
		|| ((euid + 1) > (uid_t) ((__kernel_uid_t) - 1U))) {
		__set_errno(EINVAL);
		return -1;
	}
	return (__syscall_setreuid(ruid, euid));
}
#endif

libc_hidden_def(setreuid)
