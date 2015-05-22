/* vi: set sw=4 ts=4: */
/*
 * writev() for uClibc
 *
 * Copyright (C) 2012 Ruslan Nikolaev <rnikola@vt.edu>
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <sys/uio.h>

#include <bits/sclib.h>

static __inline__ ssize_t __syscall_writev(int fd, const struct iovec *iov, int iovcnt)
{
	int sysid;
	size_t size;
	long dfd = sclib_file_getid(&sclib_file, fd, &sysid);

	SCLIB_ERR_RET(dfd);
	if (sysid != SYSCALL_SYSID_LOCAL) {
		struct sclib_iovc iovc;
		size_t ret, chunk, count = sclib_iovec_length(iov, iovcnt);
		void *rbuf, *mem;

		SCLIB_VAL2_RET(count, size);
		chunk = MIN(count, SCLIB_MAX_BUFFER);
		mem = sclib_memory_alloc(&sclib_data[sysid], chunk);
		SCLIB_MEM_RET(mem, size);
		size = 0;
		iovc.iovc_iov = iov;
		iovc.iovc_off = 0;
		rbuf = sclib_mem(sysid, mem);

		for (; count > chunk; count -= chunk) {
			sclib_copy_from_iovec(mem, &iovc, chunk);
			ret = SCLIB_REMOTE_CALL(sysid, write, 3, dfd, rbuf, chunk);
			SCLIB_VAL_RET(ret, size);
			size += ret;
			if (unlikely(ret < chunk))
				goto error_val;
		}
		sclib_copy_from_iovec(mem, &iovc, count);
		ret = SCLIB_REMOTE_CALL(sysid, write, 3, dfd, rbuf, count);
		SCLIB_VAL_RET(ret, size);
		size += ret;

error_val:
		sclib_memory_free(&sclib_data[sysid], mem);
	} else {
		size = SCLIB_LOCAL_CALL(writev, 3, dfd, iov, iovcnt);
	}

error_val2:
error_mem:
	sclib_file_put(&sclib_file, fd);
	SCLIB_ERR_RET(size);
	return size;
}

#ifdef __UCLIBC_HAS_THREADS_NATIVE__
#include <errno.h>
#include <sysdep-cancel.h>

/* We should deal with kernel which have a smaller UIO_FASTIOV as well
   as a very big count.  */
static ssize_t __writev (int fd, const struct iovec *vector, int count)
{
  ssize_t bytes_written;

  bytes_written = __syscall_writev (fd, vector, count);

  if (bytes_written >= 0 || errno != EINVAL || count <= UIO_FASTIOV)
    return bytes_written;

  /* glibc tries again, but we do not. */
  /* return __atomic_writev_replacement (fd, vector, count); */

  return -1;
}

ssize_t writev (int fd, const struct iovec *vector, int count)
{
  if (SINGLE_THREAD_P)
    return __writev (fd, vector, count);

  int oldtype = LIBC_CANCEL_ASYNC ();

  ssize_t result = __writev (fd, vector, count);

  LIBC_CANCEL_RESET (oldtype);

  return result;
}
#else
ssize_t writev(int fd, const struct iovec *vector, int count)
{
  return __syscall_writev (fd, vector, count);
}
#endif
