/* vi: set sw=4 ts=4: */
/*
 * rmdir() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <unistd.h>

#include <bits/sclib.h>

int rmdir(const char *pathname)
{
	return SCLIB_PATH_CALL(rmdir, 1, pathname);
}

libc_hidden_def(rmdir)
