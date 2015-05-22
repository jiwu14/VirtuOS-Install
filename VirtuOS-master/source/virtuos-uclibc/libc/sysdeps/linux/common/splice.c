/* vi: set sw=4 ts=4: */
/*
 * splice() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 * Copyright (C) 2012 Ruslan Nikolaev <rnikola@vt.edu>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <fcntl.h>

#include <bits/sclib.h>

#ifdef __NR_splice
ssize_t splice(int in_fd, __off64_t *in_off, int out_fd, __off64_t *out_off,
	size_t count, unsigned int flags)
{
	int out_sysid, in_sysid;
	long ret, out_dfd, in_dfd;

	out_dfd = sclib_file_getid(&sclib_file, out_fd, &out_sysid);
	if (SCLIB_IS_ERR(out_dfd)) {
		ret = out_dfd;
		goto error_out_dfd;
	}
	in_dfd = sclib_file_getid(&sclib_file, in_fd, &in_sysid);
	if (SCLIB_IS_ERR(in_dfd)) {
		ret = in_dfd;
		goto error_in_dfd;
	}

	if (out_sysid == in_sysid) {
		if (out_sysid != SYSCALL_SYSID_LOCAL) {
			ret = SCLIB_REMOTE_CALL(out_sysid, splice, 6, in_dfd, in_off ? *in_off : -1L, out_dfd, out_off ? *out_off : -1L, count, flags);
			if (!SCLIB_IS_ERR(ret)) {
				if (in_off)
					*in_off += (unsigned long) ret;
				if (out_off)
					*out_off += (unsigned long) ret;
			}
		} else {
			ret = SCLIB_LOCAL_CALL(splice, 6, in_dfd, in_off, out_dfd, out_off,
								   count, flags);
		}
	} else {
		/* Flags seem to be implementation defined, so ignore them for now */
		ret = sclib_copy64_file(in_dfd, in_off, out_dfd, out_off, count, in_sysid, out_sysid);
	}

	sclib_file_put(&sclib_file, in_fd);
error_in_dfd:
	sclib_file_put(&sclib_file, out_fd);
error_out_dfd:
	SCLIB_ERR_RET(ret);
	return ret;
}
#endif
