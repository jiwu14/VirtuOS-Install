/* vi: set sw=4 ts=4: */
/*
 * chmod() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <sys/stat.h>
#include <bits/sclib.h>

int chmod(const char *path, mode_t mode)
{
	return SCLIB_PATH_CALL(chmod, 2, path, mode);
}
libc_hidden_def(chmod)
