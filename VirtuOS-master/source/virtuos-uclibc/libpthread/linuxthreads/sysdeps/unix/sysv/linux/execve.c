/* Copyright (C) 1999, 2000, 2002 Free Software Foundation, Inc.
   Copyright (C) 2013 Ruslan Nikolaev <rnikola@vt.edu>
   This file is part of the GNU C Library.

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

#include <errno.h>
#include <unistd.h>

#include <sysdep.h>
#include <alloca.h>
#include <sys/syscall.h>

#include <bits/sclib.h>

extern int __syscall_execve(const char *file,
			char *const *argv,
			char *const *envp);
extern void __pthread_kill_other_threads_np(void);
weak_extern(__pthread_kill_other_threads_np)

int
__execve(const char *file, char *const argv[], char *const envp[])
{
	long ret;

	/* If this is a threaded application kill all other threads.  */
	if (__pthread_kill_other_threads_np)
		__pthread_kill_other_threads_np();
	ret = sclib_fds_save();
	SCLIB_ERR_RET(ret);
	return INLINE_SYSCALL(execve, 3, file, argv, envp);
}
weak_alias(__execve, execve)
