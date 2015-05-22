/*
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 * Copyright (C) 2012 Ruslan Nikolaev <rnikola@vt.edu>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */
/* Massivly hacked up for uClibc by Erik Andersen */

#include <_lfs_64.h>

#ifdef __UCLIBC_HAS_LFS__

#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <bits/uClibc_page.h>

#include <bits/sclib.h>

# if !defined __NR_mmap2

/*
 * This version is a stub that just chops off everything at the mmap 32 bit
 * mmap() address space...  You will probably need to add in an arch specific
 * implementation to override this as there is not a generic way for me to
 * implement this particular syscall if your arch lacks _syscall6...
 *
 */

__ptr_t mmap64(__ptr_t addr, size_t len, int prot, int flags, int fd, __off64_t offset)
{
	if (offset != (off_t) offset ||
	    (offset + len) != (off_t) (offset + len)) {
		__set_errno(EINVAL);
		return MAP_FAILED;
	}

	return mmap(addr, len, prot, flags, fd, (off_t) offset);
}

# else

__ptr_t __syscall_mmap2(__ptr_t addr, size_t length, int prot, int flags,
	int fd, off_t offset)
{
	long ret, lfd = -1;

	if (!(flags & MAP_ANONYMOUS)) {
		lfd = sclib_file_get(&sclib_file, fd, SYSCALL_SYSID_LOCAL);
		if (SCLIB_IS_ERR(lfd)) {
			__set_errno(-lfd);
			return (void *) -1;
		}
	}
	ret = INLINE_SYSCALL(mmap2, 6, addr, length, prot, flags, lfd, offset);
	if (!(flags & MAP_ANONYMOUS))
		sclib_file_put(&sclib_file, fd);
	return (__ptr_t) ret;
}

/* Some architectures always use 12 as page shift for mmap2() eventhough the
 * real PAGE_SHIFT != 12.  Other architectures use the same value as
 * PAGE_SHIFT...
 */
#  ifndef MMAP2_PAGE_SHIFT
#   define MMAP2_PAGE_SHIFT 12
#  endif

__ptr_t mmap64(__ptr_t addr, size_t len, int prot, int flags, int fd, __off64_t offset)
{
	if (offset & ((1 << MMAP2_PAGE_SHIFT) - 1)) {
		__set_errno(EINVAL);
		return MAP_FAILED;
	}

#  ifdef __USE_FILE_OFFSET64
	return __syscall_mmap2(addr, len, prot, flags,
	                       fd, ((__u_quad_t) offset >> MMAP2_PAGE_SHIFT));
#  else
	return __syscall_mmap2(addr, len, prot, flags,
	                       fd, ((__u_long) offset >> MMAP2_PAGE_SHIFT));
#  endif
}

# endif
#endif /* __UCLIBC_HAS_LFS__ */
