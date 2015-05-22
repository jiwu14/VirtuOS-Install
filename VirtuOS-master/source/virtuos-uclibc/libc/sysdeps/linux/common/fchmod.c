/* vi: set sw=4 ts=4: */
/*
 * fchmod() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <sys/stat.h>

#include <bits/sclib.h>

int fchmod(int fildes, mode_t mode)
{
	return SCLIB_DFD_SYSCALL(fchmod, 2, fildes, mode);
}
