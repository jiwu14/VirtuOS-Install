/* Uncancelable versions of cancelable interfaces.  Linux version.
   Copyright (C) 2003 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@redhat.com>, 2003.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

#include <sysdep.h>

#include <bits/sclib.h>
#include <bits/sclib_syscalls.h>

/* Uncancelable open.  */
static __always_inline int open_not_cancel(const char *name, int flags, mode_t mode)
{
	long ret = __internal_sys_open(name, flags, mode);
	SCLIB_ERR_RET(ret);
	return ret;
}

static __always_inline int open_not_cancel_2(const char *name, int flags)
{
	long ret = __internal_sys_open(name, flags, 0);
	SCLIB_ERR_RET(ret);
	return ret;
}

/* Uncancelable close.  */
static __always_inline int close_not_cancel(int fd)
{
	long ret = __internal_sys_close(fd);
	SCLIB_ERR_RET(ret);
	return ret;
}

static __always_inline void close_not_cancel_no_status(int fd)
{
	__internal_sys_close(fd);
}

/* Uncancelable read.  */
static __always_inline ssize_t read_not_cancel(int fd, void *buf, size_t n)
{
	return SCLIB_LFD_SYSCALL(read, 3, fd, buf, n);
}

/* Uncancelable write.  */
static __always_inline ssize_t write_not_cancel(int fd, const void *buf, size_t n)
{
	return SCLIB_LFD_SYSCALL(write, 3, fd, buf, n);
}

/* Uncancelable writev.  */
static __always_inline void writev_not_cancel_no_status(int fd, const struct iovec *iov, int n)
{
	SCLIB_LFD_SYSCALL_NOSTATUS(writev, 3, fd, iov, n);
}

/* Uncancelable fcntl.  */
#define fcntl_not_cancel(fd, cmd, val) \
  __fcntl_nocancel (fd, cmd, val)

/* Uncancelable waitpid.  */
#ifdef __NR_waitpid
# define waitpid_not_cancel(pid, stat_loc, options) \
  INLINE_SYSCALL (waitpid, 3, pid, stat_loc, options)
#else
# define waitpid_not_cancel(pid, stat_loc, options) \
  INLINE_SYSCALL (wait4, 4, pid, stat_loc, options, NULL)
#endif
