/* vi: set sw=4 ts=4: */
/*
 * ioctl() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 * Copyright (C) 2012 Ruslan Nikolaev <rnikola@vt.edu>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <stdarg.h>
#include <sys/ioctl.h>
#include <string.h>

#include <bits/sclib.h>

#ifdef __UCLIBC_HAS_THREADS_NATIVE__
#include <sysdep-cancel.h>
#else
#define SINGLE_THREAD_P 1
#endif

libc_hidden_proto(ioctl)

static int __syscall_ioctl(int fd, unsigned long int request, void *arg)
{
	int sysid;
	long ret, ifd = -1, dfd = sclib_file_getid(&sclib_file, fd, &sysid);

	SCLIB_ERR_RET(dfd);

	if (sclib_ioctl_open(request)) {
		ifd = sclib_file_add(&sclib_file, 0);
		SCLIB_VAL_RET(ifd, ret);
	}

	if (sysid != SYSCALL_SYSID_LOCAL) {
		void *mem = NULL;
		void *rarg = arg;
		unsigned dir;
		size_t size, isize, asize;

		sclib_ioctl_decode(request, &dir, &size);
		if (size > 0) {
			isize = size;
			asize = size;
			if (_IOC_TYPE(request) == PERFCTR_IOCTL_MAGIC) {
				struct perfctr_struct_buf *bufarg = arg;
				if ((dir & _IOC_WRITE) && size == sizeof(*bufarg)) {
					isize = bufarg->rdsize + sizeof(*bufarg) - 
						sizeof(bufarg->buffer);
					asize = MAX(bufarg->rdsize, bufarg->wrsize) +
						sizeof(*bufarg) - sizeof(bufarg->buffer);
				}
			}
			mem = sclib_memory_alloc(&sclib_data[sysid], asize);
			SCLIB_MEM_RET(mem, ret);
			if (dir & _IOC_WRITE)
				mem = memcpy(mem, arg, isize);
			rarg = sclib_mem(sysid, mem);
		}
		ret = SCLIB_REMOTE_CALL(sysid, ioctl, 3, dfd, request, rarg);
		if (mem) {
			if ((dir & _IOC_READ) && !SCLIB_IS_ERR(ret)) {
				if (_IOC_TYPE(request) == PERFCTR_IOCTL_MAGIC) {
					struct perfctr_cpu_mask *maskarg = mem;
					struct perfctr_struct_buf *bufarg = mem;
					if (size == sizeof(*maskarg)) {
						size = maskarg->nrwords * sizeof(maskarg->mask[0])
							+ sizeof(*maskarg) - sizeof(maskarg->mask);
					} else if (size == sizeof(*bufarg)) {
						size = bufarg->wrsize + sizeof(*bufarg) -
							sizeof(bufarg->buffer);
					}
				}
				memcpy(arg, mem, size);
			}
			sclib_memory_free(&sclib_data[sysid], mem);
		}
	} else {
		ret = SCLIB_LOCAL_CALL(ioctl, 3, dfd, request, arg);
	}

error_mem:
	if (ifd > 0) {
		if (SCLIB_IS_ERR(ret)) {
			sclib_file_add_fail(&sclib_file, ifd);
		} else {
			sclib_file_add_ok(&sclib_file, ifd, ret, sysid, 0, 0);
			ret = ifd;
		}
	}
error_val:
	sclib_file_put(&sclib_file, fd);
	SCLIB_ERR_RET(ret);
	return ret;
}

int ioctl(int fd, unsigned long int request, ...)
{
	void *arg;
	va_list list;

	va_start(list, request);
	arg = va_arg(list, void *);

	va_end(list);

	if (SINGLE_THREAD_P)
		return __syscall_ioctl(fd, request, arg);

#ifdef __UCLIBC_HAS_THREADS_NATIVE__
	int oldtype = LIBC_CANCEL_ASYNC ();
	int result = __syscall_ioctl(fd, request, arg);
	LIBC_CANCEL_RESET (oldtype);
	return result;
#endif
}
libc_hidden_def(ioctl)
