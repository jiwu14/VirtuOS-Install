/* vi: set sw=4 ts=4: */
/*
 * posix_fadvise64() for uClibc
 * http://www.opengroup.org/onlinepubs/009695399/functions/posix_fadvise.html
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <features.h>
#include <unistd.h>
#include <errno.h>
#include <endian.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <fcntl.h>

#ifdef __UCLIBC_HAS_LFS__
#ifdef __NR_fadvise64_64

/* 64 bit implementation is cake ... or more like pie ... */
#if __WORDSIZE == 64

#define __NR_posix_fadvise64 __NR_fadvise64_64

int posix_fadvise64(int fd, __off64_t offset, __off64_t len, int advice)
{
	int sysid;
	long err, dfd = sclib_file_getid(&sclib_file, fd, &sysid);

	if (len != (off_t) len)
		return EOVERFLOW;

	SCLIB_ERR_RET(dfd);
	err = SCLIB_SYSID_CALL(sysid, posix_fadvise64, 5, dfd, __LONG_LONG_PAIR((long) (offset >> 32), (long) offset), (off_t) len, advice);
	sclib_file_put(&sclib_file, fd);
	SCLIB_ERR_RET(err);
	return err;
}

/* 32 bit implementation is kind of a pita */
#elif __WORDSIZE == 32

int posix_fadvise64(int fd, __off64_t offset, __off64_t len, int advice)
{
	INTERNAL_SYSCALL_DECL (err);
	int ret = INTERNAL_SYSCALL (fadvise64_64, err, 6, fd,
								__LONG_LONG_PAIR(offset >> 32, offset &  0xffffffff),
								__LONG_LONG_PAIR(len >> 32, len & 0xffffffff),
								advice);
	if (!INTERNAL_SYSCALL_ERROR_P (ret, err))
		return 0;
	return INTERNAL_SYSCALL_ERRNO (ret, err);
}

#else
#error your machine is neither 32 bit or 64 bit ... it must be magical
#endif

#elif !defined __NR_fadvise64 && defined __UCLIBC_HAS_STUBS__
/* This is declared as a strong alias in posix_fadvise.c if __NR_fadvise64
 * is defined.
 */
int posix_fadvise64(int fd, __off64_t offset, __off64_t len, int advice)
{
	return ENOSYS;
}
#endif /* __NR_fadvise64_64 */
#endif /* __UCLIBC_HAS_LFS__ */
