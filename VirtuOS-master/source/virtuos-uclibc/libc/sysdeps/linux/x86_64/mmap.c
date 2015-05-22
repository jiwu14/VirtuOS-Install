/* vi: set sw=4 ts=4: */
/*
 * mmap() for uClibc/x86_64
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 * Copyright (C) 2005 by Mike Frysinger <vapier@gentoo.org>
 * Copyright (C) 2012 Ruslan Nikolaev <rnikola@vt.edu>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#include <bits/sclib.h>

void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
	long ret, lfd = -1;

	if (!(flags & MAP_ANONYMOUS)) {
		lfd = sclib_file_get(&sclib_file, fd, SYSCALL_SYSID_LOCAL);
		if (SCLIB_IS_ERR(lfd)) {
			__set_errno(-lfd);
			return (void *) -1;
		}
	}
	ret = INLINE_SYSCALL(mmap, 6, addr, length, prot, flags, lfd, offset);
	if (!(flags & MAP_ANONYMOUS))
		sclib_file_put(&sclib_file, fd);
	return (void *) ret;
}

libc_hidden_def(mmap)
