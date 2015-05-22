/*
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 * Copyright (C) 2012 Ruslan Nikolaev <rnikola@vt.edu>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <features.h>
#include <assert.h>
#include <errno.h>
#include <dirent.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <bits/kernel_types.h>
#include <bits/uClibc_alloc.h>

#include <bits/sclib.h>

#if defined __UCLIBC_HAS_LFS__ && defined __NR_getdents64

# ifndef offsetof
#  define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
# endif

struct kernel_dirent64
{
    uint64_t		d_ino;
    int64_t		d_off;
    unsigned short	d_reclen;
    unsigned char	d_type;
    char		d_name[256];
};

static __always_inline int __syscall_getdents64(int fd, unsigned char *kdirp,
	size_t count)
{
	long dfd, ret;
	int sysid;
	void *rbuf;
	uint8_t flags;

	dfd = sclib_file_getid(&sclib_file, fd, &sysid);
	SCLIB_ERR_RET(dfd);
	sclib_read_lock_fd_flags(&sclib_file, fd);
	flags = sclib_file.fds[fd].flags;

	if (unlikely(flags & SCLIB_FD_TRAN)) {
		const size_t alignment = __alignof__ (struct kernel_dirent64);
		struct kernel_dirent64 *tran_cur, *tran_end, *kdirp_cur;
		size_t tran_count;
		long tran_ret, tran_fd;
		int tran_dfd;

		/* Each file descriptor will require expansion of at most 4 digits;
			an alignment is at least 4 bytes. Therefore, we at most expand
			each entry by an alignment unit. */
		tran_count = (count / offsetof(struct kernel_dirent64, d_name))
						* alignment;
		if (count <= tran_count) {
			ret = -EINVAL;
			goto error_mem;
		}
		tran_count = count - tran_count;
		if (sysid == SYSCALL_SYSID_LOCAL) {
			rbuf = malloc(tran_count);
			SCLIB_MEM_RET(rbuf, ret);
			tran_ret = SCLIB_LOCAL_CALL(getdents64, 3, dfd, rbuf, tran_count);
		} else {
			rbuf = sclib_memory_alloc(&sclib_data[sysid], tran_count);
			SCLIB_MEM_RET(rbuf, ret);
			tran_ret = SCLIB_REMOTE_CALL(sysid, getdents64, 3, dfd, sclib_mem(sysid, rbuf), tran_count);
		}

		if (!SCLIB_IS_ERR(tran_ret)) { /* Translate */
			tran_cur = rbuf;
			tran_end = rbuf + tran_ret;
			kdirp_cur = (void *) kdirp;
			for (; tran_cur < tran_end;
					tran_cur = (void *) tran_cur + tran_cur->d_reclen) {
				if (tran_cur->d_name[0] == '.') { /* Not a file descriptor */
					kdirp_cur = mempcpy(kdirp_cur, tran_cur,
						tran_cur->d_reclen);
					continue;
				}
				kdirp_cur->d_ino = tran_cur->d_ino;
				kdirp_cur->d_off = tran_cur->d_off;
				kdirp_cur->d_type = tran_cur->d_type;
				if (sscanf(tran_cur->d_name, "%d", &tran_dfd) != 1 ||
					(tran_fd = sclib_file_reverse_lookup(&sclib_file,
						tran_dfd)) < 0) {
					continue;
				}
				kdirp_cur->d_reclen = sprintf(kdirp_cur->d_name, "%d",
					(int) tran_fd) + 1; /* Null-character */
				kdirp_cur->d_reclen = (kdirp_cur->d_reclen +
					offsetof(struct kernel_dirent64, d_name) +
						alignment - 1) & ~(alignment - 1);
				kdirp_cur = (void *) kdirp_cur + kdirp_cur->d_reclen;
			}
			ret = (size_t) ((void *) kdirp_cur - (void *) kdirp);
		} else {
			ret = tran_ret;
		}
		if (sysid == SYSCALL_SYSID_LOCAL) {
			free(rbuf);
		} else {
			sclib_memory_free(&sclib_data[sysid], rbuf);
		}
	} else {
		if (sysid != SYSCALL_SYSID_LOCAL) {
			rbuf = sclib_memory_alloc(&sclib_data[sysid], count);
			SCLIB_MEM_RET(rbuf, ret);
			ret = SCLIB_REMOTE_CALL(sysid, getdents64, 3, dfd, sclib_mem(sysid, rbuf), count);
			if (!SCLIB_IS_ERR(ret))
				memcpy(kdirp, rbuf, ret);
			sclib_memory_free(&sclib_data[sysid], rbuf);
		} else {
			ret = SCLIB_LOCAL_CALL(getdents64, 3, dfd, kdirp, count);
		}
	}

error_mem:
	sclib_read_unlock_fd_flags(&sclib_file, fd);
	sclib_file_put(&sclib_file, fd);
	SCLIB_ERR_RET(ret);
	return ret;
}

ssize_t __getdents64 (int fd, char *buf, size_t nbytes) attribute_hidden;
ssize_t __getdents64 (int fd, char *buf, size_t nbytes)
{
    struct dirent64 *dp;
    off64_t last_offset = -1;
    ssize_t retval;
    size_t red_nbytes;
    struct kernel_dirent64 *skdp, *kdp;
    const size_t size_diff = (offsetof (struct dirent64, d_name)
	    - offsetof (struct kernel_dirent64, d_name));

    red_nbytes = MIN (nbytes - ((nbytes /
		    (offsetof (struct dirent64, d_name) + 14)) * size_diff),
	    nbytes - size_diff);

    dp = (struct dirent64 *) buf;
    skdp = kdp = stack_heap_alloc(red_nbytes);

    retval = __syscall_getdents64(fd, (unsigned char *)kdp, red_nbytes);
    if (retval == -1) {
	stack_heap_free(skdp);
	return -1;
    }

    while ((char *) kdp < (char *) skdp + retval) {
	const size_t alignment = __alignof__ (struct dirent64);
	/* Since kdp->d_reclen is already aligned for the kernel structure
	   this may compute a value that is bigger than necessary.  */
	size_t new_reclen = ((kdp->d_reclen + size_diff + alignment - 1)
		& ~(alignment - 1));
	if ((char *) dp + new_reclen > buf + nbytes) {
	    /* Our heuristic failed.  We read too many entries.  Reset
	       the stream.  */
	    assert (last_offset != -1);
	    lseek64(fd, last_offset, SEEK_SET);

	    if ((char *) dp == buf) {
		/* The buffer the user passed in is too small to hold even
		   one entry.  */
		stack_heap_free(skdp);
		__set_errno (EINVAL);
		return -1;
	    }
	    break;
	}

	last_offset = kdp->d_off;
	dp->d_ino = kdp->d_ino;
	dp->d_off = kdp->d_off;
	dp->d_reclen = new_reclen;
	dp->d_type = kdp->d_type;
	memcpy (dp->d_name, kdp->d_name,
		kdp->d_reclen - offsetof (struct kernel_dirent64, d_name));
	dp = (struct dirent64 *) ((char *) dp + new_reclen);
	kdp = (struct kernel_dirent64 *) (((char *) kdp) + kdp->d_reclen);
    }
    stack_heap_free(skdp);
    return (char *) dp - buf;
}

#if __WORDSIZE == 64
/* since getdents doesnt give us d_type but getdents64 does, try and
 * use getdents64 as much as possible */
attribute_hidden strong_alias(__getdents64,__getdents)
#endif

#endif
