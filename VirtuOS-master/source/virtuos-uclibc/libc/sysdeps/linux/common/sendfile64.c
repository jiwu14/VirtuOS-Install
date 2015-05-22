/*
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 * Copyright (C) 2012 Ruslan Nikolaev <rnikola@vt.edu>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */
/* sendfile64 syscall.  Copes with 64 bit and 32 bit machines
 * and on 32 bit machines this sends things into the kernel as
 * two 32-bit arguments (high and low 32 bits of length) that
 * are ordered based on endianess.  It turns out endian.h has
 * just the macro we need to order things, __LONG_LONG_PAIR.
 */

#include <features.h>
#include <unistd.h>
#include <errno.h>
#include <endian.h>
#include <stdint.h>
#include <sys/sendfile.h>
#include <sys/syscall.h>
#include <bits/wordsize.h>

#include <bits/sclib.h>

#if defined __UCLIBC_HAS_LFS__ && defined __NR_sendfile64
ssize_t sendfile64(int out_fd, int in_fd, __off64_t *offset, size_t count)
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
			ret = SCLIB_REMOTE_CALL(out_sysid, sendfile64, 4, out_dfd, in_dfd, offset ? *offset : -1L, count);
			if (!SCLIB_IS_ERR(ret) && offset != NULL)
				*offset += (unsigned long) ret;
		} else {
			ret = SCLIB_LOCAL_CALL(sendfile64, 4, out_dfd, in_dfd, offset, count);
		}
	} else {
		ret = sclib_copy64_file(in_dfd, offset, out_dfd, 0, count, in_sysid, out_sysid);
	}

	sclib_file_put(&sclib_file, in_fd);
error_in_dfd:
	sclib_file_put(&sclib_file, out_fd);
error_out_dfd:
	SCLIB_ERR_RET(ret);
	return ret;
}
#endif
