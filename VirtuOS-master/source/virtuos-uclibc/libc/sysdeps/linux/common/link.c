/* vi: set sw=4 ts=4: */
/*
 * link() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <unistd.h>

#include <bits/sclib.h>

int link(const char *oldpath, const char *newpath)
{
	return SCLIB_PATH_CALL2(link, 2, oldpath, newpath);
}

