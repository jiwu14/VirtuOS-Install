/* vi: set sw=4 ts=4: */
/*
 * prctl() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <stdarg.h>
#include <linux/prctl.h>
#include <bits/sclib.h>

/* psm: including sys/prctl.h would depend on kernel headers */

#ifdef __NR_prctl
extern int prctl (int, long, long, long, long);

int prctl(int option, long _a2, long _a3, long _a4, long _a5)
{
	long ret;

	if (option == PR_CAPBSET_DROP) {
		ret = SCLIB_ALL_SIMPLE_CALL(prctl, 2, option, _a2);
	} else {
		ret = SCLIB_LOCAL_CALL(prctl, 5, option, _a2, _a3, _a4, _a5);
	}
	SCLIB_ERR_RET(ret);

	return ret;
}
#endif
