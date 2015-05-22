/* Copyright (C) 2003 Free Software Foundation, Inc.
   Copyright (C) 2013 Ruslan Nikolaev <rnikola@vt.edu>
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

#include <sched.h>
#include <signal.h>
#include <sysdep.h>
#include <tls.h>
#include <stdio.h>
#include <unistd.h>
#include <semaphore.h>
#include <string.h>
#include <sys/eventfd.h>

#include <bits/sclib.h>
#include <bits/sclib_syscalls.h>

static inline long __ARCH_FORK(void)
{
	long ret = __internal_sys_fork();
	SCLIB_ERR_RET(ret);
	return ret;
}

#define ARCH_FORK __ARCH_FORK

#include "../fork.c"
