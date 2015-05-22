/* vi: set sw=4 ts=4: */
/*
 * setgroups() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 * Copyright (C) 2012 Ruslan Nikolaev <rnikola@vt.edu>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <stdlib.h>
#include <unistd.h>
#include <grp.h>

#include <bits/sclib.h>

#ifdef __USE_BSD


#if defined(__NR_setgroups32)
# undef __NR_setgroups
# define __NR_setgroups __NR_setgroups32
_syscall2(int, setgroups, size_t, size, const gid_t *, list)

#elif __WORDSIZE == 64

int setgroups(size_t size, const gid_t *list)
{
	gid_t *rlist[SYSCALL_SYSIDS], *cur;
	syscall_entry_t *pos[SYSCALL_SYSIDS];
	long ret, rret;
	size_t sysid;

	for (sysid = 0; sysid < SYSCALL_SYSIDS; sysid++) {
		rlist[sysid] = (gid_t *) sclib_memory_alloc(&sclib_data[sysid],
									size * sizeof(gid_t));
		SCLIB_MEM_RET(rlist[sysid], ret);
		cur = memcpy(rlist[sysid], list, size * sizeof(gid_t));
		pos[sysid] = SCLIB_REMOTE_CALL_ASYNC(sysid, setgroups, 2, size,
			sclib_mem(sysid, cur));
	}

	ret = SCLIB_LOCAL_CALL(setgroups, 2, size, list);

error_mem:
	while (sysid != 0) {
		sysid--;
		rret = SCLIB_REMOTE_CALL_RESULT(sysid, setgroups, pos[sysid]);
		if (SCLIB_IS_ERR(rret))
			ret = rret;
		sclib_memory_free(&sclib_data[sysid], rlist[sysid]);
	}

	SCLIB_ERR_RET(ret);
	return ret;
}

#else


#define __NR___syscall_setgroups __NR_setgroups
static __inline__ _syscall2(int, __syscall_setgroups,
		size_t, size, const __kernel_gid_t *, list)

int setgroups(size_t size, const gid_t *groups)
{
	if (size > (size_t) sysconf(_SC_NGROUPS_MAX)) {
ret_error:
		__set_errno(EINVAL);
		return -1;
	} else {
		size_t i;
		__kernel_gid_t *kernel_groups = NULL;

		if (size) {
			kernel_groups = (__kernel_gid_t *)malloc(sizeof(*kernel_groups) * size);
			if (kernel_groups == NULL)
				goto ret_error;
		}

		for (i = 0; i < size; i++) {
			kernel_groups[i] = (groups)[i];
			if (groups[i] != (gid_t) ((__kernel_gid_t) groups[i])) {
				goto ret_error;
			}
		}

		i = __syscall_setgroups(size, kernel_groups);
		free(kernel_groups);
		return i;
	}
}
#endif

libc_hidden_def(setgroups)
#endif
