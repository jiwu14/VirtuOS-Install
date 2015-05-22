/* vi: set sw=4 ts=4: */
/*
 * mkdir() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <sys/stat.h>

#include <bits/sclib.h>

int mkdir(const char *pathname, mode_t mode)
{
	return SCLIB_PATH_CALL(mkdir, 2, pathname, mode);
}
libc_hidden_def(mkdir)
