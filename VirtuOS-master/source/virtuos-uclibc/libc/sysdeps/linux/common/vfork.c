/*
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <unistd.h>
#include <sys/types.h>
#include <sys/syscall.h>

extern __typeof(vfork) __vfork attribute_hidden;

#if 0 /* Use normal fork() for sclib */

# define __NR___vfork __NR_vfork
_syscall0(pid_t, __vfork)

weak_alias(__vfork,vfork)
libc_hidden_weak(vfork)

#else

/* Trivial implementation for arches that lack vfork */

pid_t __vfork(void)
{
    return fork();
}

weak_alias(__vfork,vfork)
libc_hidden_weak(vfork)

#endif
