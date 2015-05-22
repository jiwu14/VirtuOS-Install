/* vi: set sw=4 ts=4: */
/*
 * Copyright (C) 2012 Ruslan Nikolaev <rnikola@vt.edu>
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */
/*
 * Based in part on the files
 *		./sysdeps/unix/sysv/linux/pwrite.c,
 *		./sysdeps/unix/sysv/linux/pread.c,
 *		sysdeps/posix/pread.c
 *		sysdeps/posix/pwrite.c
 * from GNU libc 2.2.5, but reworked considerably...
 */

/* Seems to be missing in original uClibc 0.9.33 distribution for some reason.
   This version is similar and based on MIPS version.

   Ruslan Nikolaev */

#include <sys/syscall.h>
#include <unistd.h>
#include <stdint.h>
#include <endian.h>

extern __typeof(pread) __libc_pread;
extern __typeof(pwrite) __libc_pwrite;
#ifdef __UCLIBC_HAS_LFS__
extern __typeof(pread64) __libc_pread64;
extern __typeof(pwrite64) __libc_pwrite64;
#endif

#include <bits/kernel_types.h>
#include <bits/sclib.h>

#ifdef __NR_pread64

static __inline__ ssize_t __syscall_pread(int fd, void *buf, size_t count,
	off64_t offset)
{
	int sysid;
	size_t size;
	long dfd = sclib_file_getid(&sclib_file, fd, &sysid);

	SCLIB_ERR_RET(dfd);
	if (sysid != SYSCALL_SYSID_LOCAL) {
		size_t ret, chunk = MIN(count, SCLIB_MAX_BUFFER);
		void *rbuf, *mem = sclib_memory_alloc(&sclib_data[sysid], chunk);

		SCLIB_MEM_RET(mem, size);
		size = 0;
		rbuf = sclib_mem(sysid, mem);

		for (; count > chunk; count -= chunk) {
			ret = SCLIB_REMOTE_CALL(sysid, pread64, 4, dfd, rbuf, chunk, offset);
			SCLIB_VAL_RET(ret, size);
			size += ret;
			offset += ret;
			buf = mempcpy(buf, mem, ret);
			if (unlikely(ret < chunk))
				goto error_val;
		}
		ret = SCLIB_REMOTE_CALL(sysid, pread64, 4, dfd, rbuf, count, offset);
		SCLIB_VAL_RET(ret, size);
		size += ret;
		memcpy(buf, mem, ret);

error_val:
		sclib_memory_free(&sclib_data[sysid], mem);
	} else {
		size = SCLIB_LOCAL_CALL(pread64, 4, dfd, buf, count, offset);
	}

error_mem:
	sclib_file_put(&sclib_file, fd);
	SCLIB_ERR_RET(size);
	return size;
}

ssize_t __libc_pread(int fd, void *buf, size_t count, off_t offset)
{
	return __syscall_pread(fd, buf, count, offset);
}
weak_alias (__libc_pread, pread)
# ifdef __UCLIBC_HAS_LFS__
ssize_t __libc_pread64(int fd, void *buf, size_t count, off64_t offset)
{
	return __syscall_pread(fd, buf, count, offset);
}
weak_alias (__libc_pread64, pread64)
# endif /* __UCLIBC_HAS_LFS__ */

#endif /* __NR_pread */

/**********************************************************************/


#ifdef __NR_pwrite64

static __inline__ ssize_t __syscall_pwrite(int fd, const void *buf,
	size_t count, off64_t offset)
{
	int sysid;
	size_t size;
	long dfd = sclib_file_getid(&sclib_file, fd, &sysid);

	SCLIB_ERR_RET(dfd);
	if (sysid != SYSCALL_SYSID_LOCAL) {
		size_t ret, chunk = MIN(count, SCLIB_MAX_BUFFER);
		void *rbuf, *mem = sclib_memory_alloc(&sclib_data[sysid], chunk);

		SCLIB_MEM_RET(mem, size);
		size = 0;
		rbuf = sclib_mem(sysid, mem);

		for (; count > chunk; count -= chunk) {
			memcpy(mem, buf, chunk);
			buf += chunk;
			ret = SCLIB_REMOTE_CALL(sysid, pwrite64, 4, dfd, rbuf, chunk, offset);
			SCLIB_VAL_RET(ret, size);
			size += ret;
			offset += ret;
			if (unlikely(ret < chunk))
				goto error_val;
		}
		memcpy(mem, buf, count);
		ret = SCLIB_REMOTE_CALL(sysid, pwrite64, 4, dfd, rbuf, count, offset);
		SCLIB_VAL_RET(ret, size);
		size += ret;

error_val:
		sclib_memory_free(&sclib_data[sysid], mem);
	} else {
		size = SCLIB_LOCAL_CALL(pwrite64, 4, dfd, buf, count, offset);
	}

error_mem:
	sclib_file_put(&sclib_file, fd);
	SCLIB_ERR_RET(size);
	return size;
}

ssize_t __libc_pwrite(int fd, const void *buf, size_t count, off_t offset)
{
	return __syscall_pwrite(fd, buf, count, offset);
}
weak_alias (__libc_pwrite, pwrite)
# ifdef __UCLIBC_HAS_LFS__
ssize_t __libc_pwrite64(int fd, const void *buf, size_t count, off64_t offset)
{
	return __syscall_pwrite(fd, buf, count, offset);
}
weak_alias (__libc_pwrite64, pwrite64)
# endif /* __UCLIBC_HAS_LFS__  */

#endif /* __NR_pwrite */
