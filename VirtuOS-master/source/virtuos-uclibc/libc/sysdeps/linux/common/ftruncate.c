/* vi: set sw=4 ts=4: */
/*
 * ftruncate() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <unistd.h>

#include <bits/sclib.h>

int ftruncate(int fd, off_t length)
{
	return SCLIB_DFD_SYSCALL(ftruncate, 2, fd, length);
}

libc_hidden_def(ftruncate)
