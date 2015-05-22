/*
 * Copyright (C) 2004 <solar@gentoo.org>
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */
/* This file provides the following Extended Attribute system calls to uClibc.
 *
 *	setxattr(), lsetxattr(), fsetxattr(),
 *	getxattr(), lgetxattr(), fgetxattr(),
 *	listxattr(), llistxattr(), flistxattr(),
 *	removexattr(), lremovexattr(), fremovexattr()
 *
 * Dec 2004 - <solar@gentoo.org>
 */

/* Taken from the manpage.
 * On success, a positive number is returned indicating the size of the
 * extended attribute name list. On failure, -1 is returned and errno
 * is set appropriately. If extended attributes are not supported by the
 * filesystem, or are disabled, errno is set to ENOSYS.
 */

#include <sys/syscall.h>
#include <unistd.h>
#include <sys/xattr.h>

#include <bits/sclib.h>

/* sets */
#ifdef __NR_setxattr
_syscall5(int, setxattr, const char *, path, const char *, name,
	const void *, value, size_t, size, int, flags)
#endif

#ifdef __NR_lsetxattr
_syscall5(int, lsetxattr, const char *, path, const char *, name,
	const void *, value, size_t, size, int, flags)
#endif

#ifdef __NR_fsetxattr
int fsetxattr(int filedes, const char *name, const void *value, size_t size, int flags)
{
	return SCLIB_DFD_STR_INBUF_SYSCALL(fsetxattr, strlen(name) + 1, size, 5, filedes, name, value, size, flags);
}
#endif

/* gets */
#ifdef __NR_getxattr
_syscall4(ssize_t, getxattr, const char *, path, const char *, name,
	void *, value, size_t, size)
#endif

#ifdef __NR_lgetxattr
_syscall4(ssize_t, lgetxattr, const char *, path, const char *, name,
	void *, value, size_t, size)
#endif

#ifdef __NR_fgetxattr
ssize_t fgetxattr(int filedes, const char *name, void *value, size_t size)
{
	if (size > SCLIB_MAX_BUFFER)
		size = SCLIB_MAX_BUFFER;
	return SCLIB_DFD_STR_OUTBUF_SYSCALL(fgetxattr, strlen(name) + 1, size, 4, filedes, name, value, size);
}
#endif

/* list */
#ifdef __NR_listxattr
_syscall3(ssize_t, listxattr, const char *, path, char *, list, size_t,
	size)
#endif

#ifdef __NR_llistxattr
_syscall3(ssize_t, llistxattr, const char *, path, char *, list, size_t,
	size)
#endif

#ifdef __NR_flistxattr
ssize_t flistxattr(int filedes, char *list, size_t size)
{
	if (size > SCLIB_MAX_BUFFER)
		size = SCLIB_MAX_BUFFER;
	return SCLIB_DFD_OUTBUF_SYSCALL(flistxattr, size, 3, filedes, list, size);
}
#endif

/* remove */
#ifdef __NR_removexattr
int removexattr(const char *path, const char *name)
{
	return SCLIB_PATH_INBUF_CALL(removexattr, strlen(name) + 1, 2, path, name);
}
#endif

#ifdef __NR_lremovexattr
int lremovexattr(const char *path, const char *name)
{
	return SCLIB_PATH_INBUF_CALL(lremovexattr, strlen(name) + 1, 2, path, name);
}
#endif

#ifdef __NR_fremovexattr
int fremovexattr(int filedes, const char *name)
{
	return SCLIB_DFD_INBUF_SYSCALL(fremovexattr, strlen(name) + 1, 2, filedes, name);
}
#endif
