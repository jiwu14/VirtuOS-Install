/* vi: set sw=4 ts=4: */
/*
 * posix_fadvise() for uClibc
 * http://www.opengroup.org/onlinepubs/009695399/functions/posix_fadvise.html
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <fcntl.h>

#include <bits/sclib.h>

#ifdef __NR_fadvise64
#define __NR_posix_fadvise __NR_fadvise64
int posix_fadvise(int fd, off_t offset, off_t len, int advice)
{
	int sysid;
	long err, dfd = sclib_file_getid(&sclib_file, fd, &sysid);

	SCLIB_ERR_RET(dfd);
	err = SCLIB_SYSID_CALL(sysid, posix_fadvise, 5, dfd, __LONG_LONG_PAIR(offset >> 31, offset), len, advice);
	sclib_file_put(&sclib_file, fd);
	SCLIB_ERR_RET(err);
	return err;
}

#if defined __UCLIBC_HAS_LFS__ && !defined __NR_fadvise64_64
strong_alias(posix_fadvise,posix_fadvise64)
#endif

#elif defined __UCLIBC_HAS_STUBS__
int posix_fadvise(int fd attribute_unused, off_t offset attribute_unused, off_t len attribute_unused, int advice attribute_unused)
{
	return ENOSYS;
}
#endif
