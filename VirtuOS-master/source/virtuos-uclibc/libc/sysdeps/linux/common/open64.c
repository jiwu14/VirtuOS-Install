/*
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <features.h>
#include <fcntl.h>
#include <stdarg.h>
#ifdef __UCLIBC_HAS_THREADS_NATIVE__
#include <errno.h>
#include <sysdep-cancel.h>
#endif

#include <bits/sclib.h>
#include <bits/sclib_syscalls.h>

#ifdef __UCLIBC_HAS_LFS__

#ifndef O_LARGEFILE
# define O_LARGEFILE	0100000
#endif

static __inline__ int __syscall_open(const char *file, int flags, int mode)
{
	long ret = __internal_sys_open(file, flags, mode);
	SCLIB_ERR_RET(ret);
	return ret;
}

/* Open FILE with access OFLAG.  If OFLAG includes O_CREAT,
   a third argument is the file protection.  */
int open64 (const char *file, int oflag, ...)
{
    mode_t mode = 0;

    if (oflag & O_CREAT)
    {
	va_list arg;
	va_start (arg, oflag);
	mode = va_arg (arg, mode_t);
	va_end (arg);
    }

#ifdef __UCLIBC_HAS_THREADS_NATIVE__
  if (SINGLE_THREAD_P)
    return __syscall_open(file, oflag | O_LARGEFILE, mode);

  int oldtype = LIBC_CANCEL_ASYNC ();

  int result = __syscall_open(file, oflag | O_LARGEFILE, mode);

  LIBC_CANCEL_RESET (oldtype);

  return result;
#else
  return open(file, oflag | O_LARGEFILE, mode);
#endif
}
#ifndef __LINUXTHREADS_OLD__
libc_hidden_def(open64)
#else
libc_hidden_weak(open64)
strong_alias(open64,__libc_open64)
#endif

#endif /* __UCLIBC_HAS_LFS__ */
