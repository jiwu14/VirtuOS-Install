/* vi: set sw=4 ts=4: */
/*
 * __syscall_fcntl() for uClibc
 *
 * Copyright (C) 2006 Steven J. Hill <sjhill@realitydiluted.com>
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 * Copyright (C) 2012 Ruslan Nikolaev <rnikola@vt.edu>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <stdarg.h>
#ifdef __UCLIBC_HAS_THREADS_NATIVE__
#include <sysdep-cancel.h>	/* Must come before <fcntl.h>.  */
#endif
#include <fcntl.h>
#include <bits/wordsize.h>

#include <string.h>

#include <bits/sclib.h>

static long __syscall_dup(long fd, long cmd, unsigned long start_fd)
{
	int sysid;
	long dup_fd, dup_dfd, dfd;

	dfd = sclib_file_getid(&sclib_file, fd, &sysid);
	SCLIB_ERR_RET(dfd);
	dup_fd = sclib_file_add(&sclib_file, start_fd);
	SCLIB_VAL_RET(dup_fd, dup_dfd);

	__sync_fetch_and_or(&sclib_file.fds[fd].ectl_doms, 0xFF);

	switch (sysid)
	{
	default:
		dup_dfd = SCLIB_REMOTE_CALL(sysid, fcntl, 3, dfd, cmd, 0);
		break;

	case SYSCALL_SYSID_LOCAL:
		dup_dfd = SCLIB_LOCAL_CALL(fcntl, 3, dfd, cmd, 0);
		break;

	case SYSCALL_SYSID_ALL:
	{
		sclib_fd_t *aux, *dup_aux;
		size_t n, i;

		aux = sclib_file_aux(&sclib_file, fd);
		dup_aux = sclib_file_aux(&sclib_file, dup_fd);
		for (n = 0; n < SYSCALL_SYSIDS; n++) {
			dup_aux[n] = SCLIB_REMOTE_CALL(n, fcntl, 3, aux[n], cmd, 0);
			if (SCLIB_IS_ERR(dup_aux[n])) {
				dup_dfd = dup_aux[n];
				goto error_aux;
			}
		}
		dup_dfd = SCLIB_LOCAL_CALL(fcntl, 3, dfd, cmd, 0);
		if (SCLIB_IS_ERR(dup_dfd)) {
error_aux:
			for (i = 0; i < n; i++)
				SCLIB_REMOTE_CALL(i, close, 1, dup_aux[i]);
		}
		break;
	}
	}

	if (SCLIB_IS_ERR(dup_dfd)) {
		sclib_file_add_fail(&sclib_file, dup_fd);
	} else {
		uint8_t dup_dfd_flags = 0;
		if (cmd == F_DUPFD_CLOEXEC)
			dup_dfd_flags |= SCLIB_FD_EXEC;
		sclib_file_add_ok(&sclib_file, dup_fd, dup_dfd, sysid, dup_dfd_flags, 0xFF);
	}

error_val:
	sclib_file_put(&sclib_file, fd);	
	SCLIB_ERR_RET(dup_dfd);
	return dup_fd;
}

static long __syscall_fcntl(long fd, long cmd, void *arg)
{
	int sysid;
	long dfd, ret;

	/* Use a different mechanism for dup operations */
	if (cmd == F_DUPFD || cmd == F_DUPFD_CLOEXEC)
		return __syscall_dup(fd, cmd, (unsigned long) arg);

	dfd = sclib_file_getid(&sclib_file, fd, &sysid);
	SCLIB_ERR_RET(dfd);

	if (cmd == F_SETFD)
		sclib_write_lock_fd_flags(&sclib_file, fd);

	switch (sysid)
	{
	default:
	{
		void *mem = NULL;
		void *rarg = arg;
		unsigned dir;
		size_t size;

		sclib_fcntl_decode(cmd, &dir, &size);
		if (size > 0) {
			mem = sclib_memory_alloc(&sclib_data[sysid], size);
			SCLIB_MEM_RET(mem, ret);
			if (dir & _IOC_WRITE)
				mem = memcpy(mem, arg, size);
			rarg = sclib_mem(sysid, mem);
		}
		ret = SCLIB_REMOTE_CALL(sysid, fcntl, 3, dfd, cmd, rarg);
		if (mem) {
			if ((dir & _IOC_READ) && !SCLIB_IS_ERR(ret))
				memcpy(arg, mem, size);
			sclib_memory_free(&sclib_data[sysid], mem);
		}
		break;
	}

	case SYSCALL_SYSID_LOCAL:
		ret = SCLIB_LOCAL_CALL(fcntl, 3, dfd, cmd, arg);
		break;

	case SYSCALL_SYSID_ALL:
	{
		sclib_fd_t *aux = sclib_file_aux(&sclib_file, fd);
		void *mem = mem;
		void *rarg = arg;
		unsigned dir;
		size_t n, size;

		sclib_fcntl_decode(cmd, &dir, &size);
		for (n = 0; n < SYSCALL_SYSIDS; n++) {
			if (size > 0) {
				mem = sclib_memory_alloc(&sclib_data[n], size);
				SCLIB_MEM_RET(mem, ret);
				if (dir & _IOC_WRITE)
					mem = memcpy(mem, arg, size);
				rarg = sclib_mem(n, mem);
			}
			ret = SCLIB_REMOTE_CALL(n, fcntl, 3, aux[n], cmd, rarg);
			if (size > 0) {
				if ((dir & _IOC_READ) && !SCLIB_IS_ERR(ret))
					memcpy(arg, mem, size);
				sclib_memory_free(&sclib_data[n], mem);
			}
			if (SCLIB_IS_ERR(ret))
				goto error_mem;
		}
		ret = SCLIB_LOCAL_CALL(fcntl, 3, dfd, cmd, arg);
		break;
	}
	}

error_mem:
	if (cmd == F_SETFD) {
		if (!SCLIB_IS_ERR(ret)) {
			if ((long) arg & FD_CLOEXEC)
				sclib_file.fds[fd].flags |= SCLIB_FD_EXEC;
			else
				sclib_file.fds[fd].flags &= ~SCLIB_FD_EXEC;
		}
		sclib_write_unlock_fd_flags(&sclib_file, fd);
	}
	sclib_file_put(&sclib_file, fd);

	SCLIB_ERR_RET(ret);
	return ret;
}

extern __typeof(fcntl) __libc_fcntl;
libc_hidden_proto(__libc_fcntl)

int __fcntl_nocancel (int fd, int cmd, ...)
{
	va_list ap;
	void *arg;

	va_start (ap, cmd);
	arg = va_arg (ap, void *);
	va_end (ap);

# if __WORDSIZE == 32
	if (cmd == F_GETLK64 || cmd == F_SETLK64 || cmd == F_SETLKW64) {
#  if defined __UCLIBC_HAS_LFS__ && defined __NR_fcntl64
		return INLINE_SYSCALL (fcntl64, 3, fd, cmd, arg);
#  else
		__set_errno(ENOSYS);
		return -1;
#  endif
	}
# endif
	return __syscall_fcntl(fd, cmd, arg);
}
libc_hidden_def(__fcntl_nocancel)

int __libc_fcntl (int fd, int cmd, ...)
{
	va_list ap;
	void *arg;

	va_start (ap, cmd);
	arg = va_arg (ap, void *);
	va_end (ap);

#ifdef __UCLIBC_HAS_THREADS_NATIVE__
	if (SINGLE_THREAD_P || (cmd != F_SETLKW && cmd != F_SETLKW64))
# if defined __UCLIBC_HAS_LFS__ && defined __NR_fcntl64
		return INLINE_SYSCALL (fcntl64, 3, fd, cmd, arg);
# else
		return __syscall_fcntl(fd, cmd, arg);
# endif

	int oldtype = LIBC_CANCEL_ASYNC ();

# if defined __UCLIBC_HAS_LFS__ && defined __NR_fcntl64
	int result = INLINE_SYSCALL (fcntl64, 3, fd, cmd, arg);
# else
	int result = __syscall_fcntl(fd, cmd, arg);
# endif

	LIBC_CANCEL_RESET (oldtype);

	return result;
#else
# if __WORDSIZE == 32
	if (cmd == F_GETLK64 || cmd == F_SETLK64 || cmd == F_SETLKW64) {
#  if defined __UCLIBC_HAS_LFS__ && defined __NR_fcntl64
		return INLINE_SYSCALL (fcntl64, 3, fd, cmd, arg);
#  else
		__set_errno(ENOSYS);
		return -1;
#  endif
	}
# endif
	return __syscall_fcntl(fd, cmd, arg);
#endif
}
libc_hidden_def(__libc_fcntl)

libc_hidden_proto(fcntl)
weak_alias(__libc_fcntl,fcntl)
libc_hidden_weak(fcntl)
