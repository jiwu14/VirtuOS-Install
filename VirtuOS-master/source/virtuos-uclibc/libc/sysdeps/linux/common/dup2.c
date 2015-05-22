/* vi: set sw=4 ts=4: */
/*
 * dup2() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 * Copyright (C) 2012 Ruslan Nikolaev <rnikola@vt.edu>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <unistd.h>

#include <bits/sclib.h>

int dup2(int fd, int dup_fd)
{
	int sysid;
	long dfd, dup_dfd;
	sclib_fd_t dup_aux[SYSCALL_SYSIDS];

	if (unlikely((unsigned int) dup_fd >= SCLIB_FILE_TABLE_LENGTH)) {
		__set_errno(EBADF);
		return -1;
	}
	if (fd == dup_fd)
		return fd;
	dfd = sclib_file_getid(&sclib_file, fd, &sysid);
	SCLIB_ERR_RET(dfd);

	__sync_fetch_and_or(&sclib_file.fds[fd].ectl_doms, 0xFF);

	switch (sysid)
	{
	default:
		dup_dfd = SCLIB_REMOTE_CALL(sysid, dup, 1, dfd);
		break;

	case SYSCALL_SYSID_LOCAL:
		dup_dfd = SCLIB_LOCAL_CALL(dup, 1, dfd);
		break;

	case SYSCALL_SYSID_ALL:
	{
		sclib_fd_t *aux;
		size_t n, i;

		aux = sclib_file_aux(&sclib_file, fd);
		for (n = 0; n < SYSCALL_SYSIDS; n++) {
			dup_aux[n] = SCLIB_REMOTE_CALL(n, dup, 1, aux[n]);
			if (SCLIB_IS_ERR(dup_aux[n])) {
				dup_dfd = dup_aux[n];
				goto error_aux;
			}
		}
		dup_dfd = SCLIB_LOCAL_CALL(dup, 1, dfd);
		if (SCLIB_IS_ERR(dup_dfd)) {
error_aux:
			for (i = 0; i < n; i++)
				SCLIB_REMOTE_CALL(i, close, 1, dup_aux[i]);
		}
		break;
	}
	}

	sclib_file_put(&sclib_file, fd);
	SCLIB_ERR_RET(dup_dfd);
	sclib_file_replace(&sclib_file, dup_fd, dup_dfd, sysid, dup_aux);
	return dup_fd;
}

libc_hidden_def(dup2)
