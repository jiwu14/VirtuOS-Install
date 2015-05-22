/**
 * VM-Syscalls
 * Copyright (c) 2012 Ruslan Nikolaev <rnikola@vt.edu>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#ifndef _SCLIB_PUBLIC_H
#define _SCLIB_PUBLIC_H 1

#include <inttypes.h>
#include <sys/types.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/param.h>
#include <fcntl.h>
#include <unistd.h>
#include <features.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>

/* A special value for epoll */
#define EPOLLEFD	(1 << 23)

#define SCLIB_LIB_PATH			"/usr/sclib/lib"
#define SCLIB_STORAGE_PREFIX	"/storage"
#define SCLIB_MAX_BUFFER		(SYSCALL_DATA_SHARED_PAGES * PAGE_SIZE) / 8

#define smp_mb()				__sync_synchronize()

#ifndef likely
# define likely(x)				__builtin_expect((x),1)
#endif
#ifndef unlikely
# define unlikely(x)			__builtin_expect((x),0)
#endif

#include "_syscall.h"
#include "_syscall_stack.h"
#include "_syscall_num.h"

#define SYSCALL_SYSID_ALL		-1
#define SYSCALL_SYSID_LOCAL		SYSCALL_SYSIDS

struct syscall_efd {
	uint64_t efd_num;
	int n;
	int efd[SYSCALL_SYSIDS+1];
};

/* Sclib iovec cookie */
struct sclib_iovc {
	const struct iovec *iovc_iov;
	size_t iovc_off;
};

#define SCLIB_IS_ERR(x)	\
	(unlikely((unsigned long) (x) >= (unsigned long) (-4095L)))

#define SCLIB_ERR_RET(x) \
	do { \
		if (SCLIB_IS_ERR(x)) { \
			__set_errno(-(x)); \
			return -1; \
		} \
	} while (0);

#define SCLIB_SYS_RET(x) \
	do { \
		if (SCLIB_IS_ERR(x)) \
			return (x); \
	} while (0);

#define SCLIB_VAL_RET(e, r) \
	do { \
		if (SCLIB_IS_ERR(e)) { \
			(r) = (e); \
			goto error_val; \
		} \
	} while (0);

#define SCLIB_VAL2_RET(e, r) \
	do { \
		if (SCLIB_IS_ERR(e)) { \
			(r) = (e); \
			goto error_val2; \
		} \
	} while (0);

#define SCLIB_MEM_RET(x, r) \
	do { \
		if (unlikely((x) == NULL)) { \
			(r) = -ENOMEM; \
			goto error_mem; \
		} \
	} while (0);

#define SCLIB_DFD_SYSCALL(call, par, fd, ...) (__extension__ ({ \
	long __ret, __dfd; \
	int __sysid; \
	__dfd = sclib_file_getid(&sclib_file, (fd), &__sysid); \
	SCLIB_ERR_RET(__dfd); \
	__ret = SCLIB_SYSID_CALL(__sysid, call, par, __dfd, ##__VA_ARGS__); \
	sclib_file_put(&sclib_file, (fd)); \
	SCLIB_ERR_RET(__ret); \
	__ret; }))

#define SCLIB_DFD_INBUF_SYSCALL(call, sz, par, fd, buf, ...) (__extension__ ({ \
	long __ret, __dfd; \
	int __sysid; \
	void *__rbuf; \
	size_t __sz; \
	__dfd = sclib_file_getid(&sclib_file, (fd), &__sysid); \
	SCLIB_ERR_RET(__dfd); \
	if (__sysid != SYSCALL_SYSID_LOCAL) { \
		__sz = (sz); \
		__rbuf = sclib_memory_alloc(&sclib_data[__sysid], __sz); \
		SCLIB_MEM_RET(__rbuf, __ret); \
		__rbuf = memcpy(__rbuf, (buf), __sz); \
		__ret = SCLIB_REMOTE_CALL(__sysid, call, par, __dfd, sclib_mem(__sysid, __rbuf), ##__VA_ARGS__); \
		sclib_memory_free(&sclib_data[__sysid], __rbuf); \
	} else { \
		__ret = SCLIB_LOCAL_CALL(call, par, __dfd, (buf), ##__VA_ARGS__); \
	} \
error_mem: \
	sclib_file_put(&sclib_file, (fd)); \
	SCLIB_ERR_RET(__ret); \
	__ret; }))

#define SCLIB_DFD_STR_INBUF_SYSCALL(call, sz1, sz2, par, fd, str, buf, ...) (__extension__ ({ \
	long __ret, __dfd; \
	int __sysid; \
	void *__rbuf, *__off; \
	size_t __sz1, __sz2; \
	__dfd = sclib_file_getid(&sclib_file, (fd), &__sysid); \
	SCLIB_ERR_RET(__dfd); \
	if (__sysid != SYSCALL_SYSID_LOCAL) { \
		__sz1 = (sz1); \
		__sz2 = (sz2); \
		__rbuf = sclib_memory_alloc(&sclib_data[__sysid], __sz1 + __sz2); \
		SCLIB_MEM_RET(__rbuf, __ret); \
		memcpy(mempcpy(__rbuf, (buf), __sz2), str, __sz1); \
		__off = sclib_mem(__sysid, __rbuf); \
		__ret = SCLIB_REMOTE_CALL(__sysid, call, par, __dfd, __off + __sz2, __off, ##__VA_ARGS__); \
		sclib_memory_free(&sclib_data[__sysid], __rbuf); \
	} else { \
		__ret = SCLIB_LOCAL_CALL(call, par, __dfd, str, buf, ##__VA_ARGS__); \
	} \
error_mem: \
	sclib_file_put(&sclib_file, (fd)); \
	SCLIB_ERR_RET(__ret); \
	__ret; }))

#define SCLIB_DFD_OUTBUF_SYSCALL(call, sz, par, fd, buf, ...) (__extension__ ({ \
	long __ret, __dfd; \
	int __sysid; \
	void *__rbuf; \
	size_t __sz; \
	__dfd = sclib_file_getid(&sclib_file, (fd), &__sysid); \
	SCLIB_ERR_RET(__dfd); \
	if (__sysid != SYSCALL_SYSID_LOCAL) { \
		__sz = (sz); \
		__rbuf = sclib_memory_alloc(&sclib_data[__sysid], __sz); \
		SCLIB_MEM_RET(__rbuf, __ret); \
		__ret = SCLIB_REMOTE_CALL(__sysid, call, par, __dfd, sclib_mem(__sysid, __rbuf), ##__VA_ARGS__); \
		if (!SCLIB_IS_ERR(__ret)) \
			memcpy((buf), __rbuf, __ret); \
		sclib_memory_free(&sclib_data[__sysid], __rbuf); \
	} else { \
		__ret = SCLIB_LOCAL_CALL(call, par, __dfd, (buf), ##__VA_ARGS__); \
	} \
error_mem: \
	sclib_file_put(&sclib_file, (fd)); \
	SCLIB_ERR_RET(__ret); \
	__ret; }))

#define SCLIB_DFD_OUTBUFSZ_SYSCALL(call, sz, par, fd, buf, ...) (__extension__ ({ \
	long __ret, __dfd; \
	int __sysid; \
	void *__rbuf; \
	size_t __sz; \
	__dfd = sclib_file_getid(&sclib_file, (fd), &__sysid); \
	SCLIB_ERR_RET(__dfd); \
	if (__sysid != SYSCALL_SYSID_LOCAL) { \
		__sz = (sz); \
		__rbuf = sclib_memory_alloc(&sclib_data[__sysid], __sz); \
		SCLIB_MEM_RET(__rbuf, __ret); \
		__ret = SCLIB_REMOTE_CALL(__sysid, call, par, __dfd, sclib_mem(__sysid, __rbuf), ##__VA_ARGS__); \
		if (!SCLIB_IS_ERR(__ret)) \
			memcpy((buf), __rbuf, __sz); \
		sclib_memory_free(&sclib_data[__sysid], __rbuf); \
	} else { \
		__ret = SCLIB_LOCAL_CALL(call, par, __dfd, (buf), ##__VA_ARGS__); \
	} \
error_mem: \
	sclib_file_put(&sclib_file, (fd)); \
	SCLIB_ERR_RET(__ret); \
	__ret; }))

#define SCLIB_DFD_STR_OUTBUF_SYSCALL(call, sz1, sz2, par, fd, str, buf, ...) (__extension__ ({ \
	long __ret, __dfd; \
	int __sysid; \
	void *__rbuf, *__off; \
	size_t __sz1, __sz2; \
	__dfd = sclib_file_getid(&sclib_file, (fd), &__sysid); \
	SCLIB_ERR_RET(__dfd); \
	if (__sysid != SYSCALL_SYSID_LOCAL) { \
		__sz1 = (sz1); \
		__sz2 = (sz2); \
		__rbuf = sclib_memory_alloc(&sclib_data[__sysid], __sz1 + __sz2); \
		SCLIB_MEM_RET(__rbuf, __ret); \
		memcpy(__rbuf + __sz2, str, __sz1); \
		__off = sclib_mem(__sysid, __rbuf); \
		__ret = SCLIB_REMOTE_CALL(__sysid, call, par, __dfd, __off + __sz2, __off, ##__VA_ARGS__); \
		if (!SCLIB_IS_ERR(__ret)) \
			memcpy((buf), __rbuf, __ret); \
		sclib_memory_free(&sclib_data[__sysid], __rbuf); \
	} else { \
		__ret = SCLIB_LOCAL_CALL(call, par, __dfd, str, (buf), ##__VA_ARGS__); \
	} \
error_mem: \
	sclib_file_put(&sclib_file, (fd)); \
	SCLIB_ERR_RET(__ret); \
	__ret; }))

#define SCLIB_LFD_SYSCALL(call, par, fd, ...) (__extension__ ({ \
	long __ret, __lfd; \
	__lfd = sclib_file_get(&sclib_file, (fd), SYSCALL_SYSID_LOCAL); \
	SCLIB_ERR_RET(__lfd); \
	__ret = SCLIB_LOCAL_CALL(call, par, __lfd, ##__VA_ARGS__); \
	sclib_file_put(&sclib_file, (fd)); \
	SCLIB_ERR_RET(__ret); \
	__ret; }))

#define SCLIB_LFDPATH_SYSCALL(call, par, fd, path, ...) (__extension__ ({ \
	long __ret, __lfd; \
	size_t __sz; \
	int __sysid; \
	char __abspath[PATH_MAX], *__dpath; \
	__dpath = sclib_get_path(__abspath, (path), &__sysid, &__sz); \
	if (__sysid != SYSCALL_SYSID_LOCAL) { \
		__set_errno(EINVAL); \
		return -1; \
	} \
	__lfd = sclib_file_get(&sclib_file, (fd), SYSCALL_SYSID_LOCAL); \
	SCLIB_ERR_RET(__lfd); \
	__ret = SCLIB_LOCAL_CALL(call, par, __lfd, __dpath, ##__VA_ARGS__); \
	sclib_file_put(&sclib_file, (fd)); \
	SCLIB_ERR_RET(__ret); \
	__ret; }))

#define SCLIB_LFD_SYSCALL2(call, par, fd1, fd2, ...) (__extension__ ({ \
	long __ret, __lfd1, __lfd2; \
	__lfd1 = sclib_file_get(&sclib_file, (fd1), SYSCALL_SYSID_LOCAL); \
	if (SCLIB_IS_ERR(__lfd1)) { \
		__ret = __lfd1; \
		goto __lfd1_err; \
	} \
	__lfd2 = sclib_file_get(&sclib_file, (fd2), SYSCALL_SYSID_LOCAL); \
	if (SCLIB_IS_ERR(__lfd2)) { \
		__ret = __lfd2; \
		goto __lfd2_err; \
	} \
	__ret = SCLIB_LOCAL_CALL(call, par, __lfd1, __lfd2, ##__VA_ARGS__); \
	sclib_file_put(&sclib_file, (fd2)); \
__lfd2_err: sclib_file_put(&sclib_file, (fd1)); \
__lfd1_err:	SCLIB_ERR_RET(__ret); \
	__ret; }))

#define SCLIB_DFD_SYSCALL_AT(call, par, fd, path, ...) (__extension__ ({ \
	const char *__dpath = (const char *) (path); \
	char __abspath[PATH_MAX]; \
	void *__rbuf = __rbuf, *__off; \
	size_t __sz; \
	int __sysid; \
	long __ret, __dfd; \
	if ((fd) == AT_FDCWD) {	\
		__dpath = sclib_get_path(__abspath, __dpath ? __dpath : "", &__sysid, &__sz); \
		__dfd = -1; \
	} else if (__dpath && *__dpath == '/') { \
		__dpath = sclib_get_path(__abspath, __dpath, &__sysid, &__sz); \
		__dfd = -1; \
	} else { \
		__sz = __dpath ? (strlen(__dpath) + 1) : 0; \
		__dfd = sclib_file_getid(&sclib_file, (fd), &__sysid); \
		SCLIB_ERR_RET(__dfd); \
	} \
	if (__sysid != SYSCALL_SYSID_LOCAL) { \
		__off = NULL; \
		if (__sz != 0) { \
			__rbuf = sclib_memory_alloc(&sclib_data[__sysid], __sz); \
			SCLIB_MEM_RET(__rbuf, __ret); \
			memcpy(__rbuf, __dpath, __sz); \
			__off = sclib_mem(__sysid, __rbuf); \
		} \
		__ret = SCLIB_REMOTE_CALL(__sysid, call, par, __dfd, __off, ##__VA_ARGS__); \
		if (__sz != 0) \
			sclib_memory_free(&sclib_data[__sysid], __rbuf); \
	} else { \
		__ret = SCLIB_LOCAL_CALL(call, par, __dfd, __dpath, ##__VA_ARGS__); \
	} \
error_mem: \
	if (__dfd >= 0) \
		sclib_file_put(&sclib_file, (fd)); \
	SCLIB_ERR_RET(__ret); \
	__ret; }))

#define SCLIB_DFD_INBUF_SYSCALL_AT(call, sz, par, fd, path, buf, ...) (__extension__ ({ \
	const char *__dpath = (const char *) (path); \
	char __abspath[PATH_MAX]; \
	void *__rbuf = __rbuf, *__off; \
	size_t __sz2, __sz1; \
	int __sysid; \
	long __ret, __dfd; \
	if ((fd) == AT_FDCWD) {	\
		__dpath = sclib_get_path(__abspath, __dpath ? __dpath : "", &__sysid, &__sz2); \
		__dfd = -1; \
	} else if (__dpath && *__dpath == '/') { \
		__dpath = sclib_get_path(__abspath, __dpath, &__sysid, &__sz2); \
		__dfd = -1; \
	} else { \
		__sz2 = __dpath ? (strlen(__dpath) + 1) : 0; \
		__dfd = sclib_file_getid(&sclib_file, (fd), &__sysid); \
		SCLIB_ERR_RET(__dfd); \
	} \
	if (__sysid != SYSCALL_SYSID_LOCAL) { \
		__sz1 = (sz); \
		__off = NULL; \
		if (__sz1 + __sz2 != 0) { \
			__rbuf = sclib_memory_alloc(&sclib_data[__sysid], __sz1 + __sz2); \
			SCLIB_MEM_RET(__rbuf, __ret); \
			memcpy(mempcpy(__rbuf, (buf), __sz1), __dpath, __sz2); \
			__off = sclib_mem(__sysid, __rbuf); \
		} \
		__ret = SCLIB_REMOTE_CALL(__sysid, call, par, __dfd, __sz2 ? (__off + __sz1) : NULL, __off, ##__VA_ARGS__); \
		if (__sz1 + __sz2 != 0) \
			sclib_memory_free(&sclib_data[__sysid], __rbuf); \
	} else { \
		__ret = SCLIB_LOCAL_CALL(call, par, __dfd, __dpath, (buf), ##__VA_ARGS__); \
	} \
error_mem: \
	if (__dfd >= 0) \
		sclib_file_put(&sclib_file, (fd)); \
	SCLIB_ERR_RET(__ret); \
	__ret; }))

#define SCLIB_DFD_SYSCALL_AT2(call, par, fd1, path1, fd2, path2, ...) (__extension__ ({ \
	const char *__dpath1 = (const char *) (path1); \
	const char *__dpath2 = (const char *) (path2); \
	char __abspath1[PATH_MAX], __abspath2[PATH_MAX]; \
	void *__rbuf = __rbuf, *__off; \
	size_t __sz2, __sz1; \
	int __sysid, __sysid2; \
	long __ret, __dfd1, __dfd2; \
	if ((fd1) == AT_FDCWD) { \
		__dpath1 = sclib_get_path(__abspath1, __dpath1 ? __dpath1 : "", &__sysid, &__sz1); \
		__dfd1 = -1; \
	} else if (__dpath1 && *__dpath1 == '/') { \
		__dpath1 = sclib_get_path(__abspath1, __dpath1, &__sysid, &__sz1); \
		__dfd1 = -1; \
	} else { \
		__sz1 = __dpath1 ? (strlen(__dpath1) + 1) : 0; \
		__dfd1 = sclib_file_getid(&sclib_file, (fd1), &__sysid); \
		__ret = __dfd1; \
		goto __dfd1_err; \
	} \
	if ((fd2) == AT_FDCWD) { \
		__dpath2 = sclib_get_path(__abspath2, __dpath2 ? __dpath2 : "", &__sysid2, &__sz2); \
		__dfd2 = -1; \
	} else if (__dpath2 && *__dpath2 == '/') { \
		__dpath2 = sclib_get_path(__abspath2, __dpath2, &__sysid2, &__sz2); \
		__dfd2 = -1; \
	} else { \
		__sz2 = __dpath2 ? (strlen(__dpath2) + 1) : 0; \
		__dfd2 = sclib_file_getid(&sclib_file, (fd2), &__sysid2); \
		__ret = __dfd2; \
		goto __dfd2_err; \
	} \
	if (__sysid != __sysid2) { \
		__ret = -EINVAL; \
		goto error_mem; \
	} \
	if (__sysid != SYSCALL_SYSID_LOCAL) { \
		__off = NULL; \
		if (__sz1 + __sz2 != 0) { \
			__rbuf = sclib_memory_alloc(&sclib_data[__sysid], __sz1 + __sz2); \
			SCLIB_MEM_RET(__rbuf, __ret); \
			memcpy(mempcpy(__rbuf, __dpath1, __sz1), __dpath2, __sz2); \
			__off = sclib_mem(__sysid, __rbuf); \
		} \
		__ret = SCLIB_REMOTE_CALL(__sysid, call, par, __dfd1, __off, __dfd2, __sz2 ? (__off + __sz1) : NULL, ##__VA_ARGS__); \
		if (__sz1 + __sz2 != 0) \
			sclib_memory_free(&sclib_data[__sysid], __rbuf); \
	} else { \
		__ret = SCLIB_LOCAL_CALL(call, par, __dfd1, __dpath1, __dfd2, __dpath2, ##__VA_ARGS__); \
	} \
error_mem: \
	if (__dfd2 >= 0) \
		sclib_file_put(&sclib_file, (fd2)); \
__dfd2_err: \
	if (__dfd1 >= 0) \
		sclib_file_put(&sclib_file, (fd1)); \
__dfd1_err: \
	SCLIB_ERR_RET(__ret); \
	__ret; }))

#define SCLIB_LFD_SYSCALL_NOSTATUS(call, par, fd, ...) (__extension__ ({ \
	INTERNAL_SYSCALL_DECL(__err); \
	long __lfd = sclib_file_get(&sclib_file, (fd), SYSCALL_SYSID_LOCAL); \
	if (unlikely(__lfd < 0)) \
		return; \
	INTERNAL_SYSCALL(call, __err, par, __lfd, ##__VA_ARGS__); \
	sclib_file_put(&sclib_file, (fd)); \
}))

#define SCLIB_PATH_CALL(call, par, path, ...) (__extension__ ({ \
	char __abspath[PATH_MAX], *__dpath; \
	long __ret; \
	int __sysid; \
	void *__rbuf; \
	size_t __sz; \
	__dpath = sclib_get_path(__abspath, (path), &__sysid, &__sz); \
	if (__sysid != SYSCALL_SYSID_LOCAL) { \
		__rbuf = sclib_memory_alloc(&sclib_data[__sysid], __sz); \
		SCLIB_MEM_RET(__rbuf, __ret); \
		memcpy(__rbuf, __dpath, __sz); \
		__ret = SCLIB_REMOTE_CALL(__sysid, call, par, sclib_mem(__sysid, __rbuf), ##__VA_ARGS__); \
		sclib_memory_free(&sclib_data[__sysid], __rbuf); \
	} else { \
		__ret = SCLIB_LOCAL_CALL(call, par, __dpath, ##__VA_ARGS__); \
	} \
error_mem: \
	SCLIB_ERR_RET(__ret); \
	__ret; }))

#define SCLIB_PATH_INBUF_CALL(call, sz, par, path, buf, ...) (__extension__ ({ \
	char __abspath[PATH_MAX], *__dpath; \
	long __ret; \
	int __sysid; \
	void *__rbuf, *__off; \
	size_t __sz1, __sz2; \
    __dpath = sclib_get_path(__abspath, (path), &__sysid, &__sz2); \
	if (__sysid != SYSCALL_SYSID_LOCAL) { \
		__sz1 = (sz); \
		__rbuf = sclib_memory_alloc(&sclib_data[__sysid], __sz1 + __sz2); \
		SCLIB_MEM_RET(__rbuf, __ret); \
		memcpy(mempcpy(__rbuf, (buf), __sz1), __dpath, __sz2); \
		__off = sclib_mem(__sysid, __rbuf); \
		__ret = SCLIB_REMOTE_CALL(__sysid, call, par, __off + __sz1, __off, ##__VA_ARGS__); \
		sclib_memory_free(&sclib_data[__sysid], __rbuf); \
	} else { \
		__ret = SCLIB_LOCAL_CALL(call, par, __dpath, (buf), ##__VA_ARGS__); \
	} \
error_mem: \
	SCLIB_ERR_RET(__ret); \
	__ret; }))

#define SCLIB_PATH_OUTBUF_CALL(call, sz, par, path, buf, ...) (__extension__ ({ \
	char __abspath[PATH_MAX], *__dpath; \
	long __ret; \
	int __sysid; \
	void *__rbuf, *__off; \
	size_t __sz1, __sz2; \
    __dpath = sclib_get_path(__abspath, (path), &__sysid, &__sz2); \
	if (__sysid != SYSCALL_SYSID_LOCAL) { \
		__sz1 = (sz); \
		__rbuf = sclib_memory_alloc(&sclib_data[__sysid], __sz1 + __sz2); \
		SCLIB_MEM_RET(__rbuf, __ret); \
		memcpy(__rbuf + __sz1, __dpath, __sz2); \
		__off = sclib_mem(__sysid, __rbuf); \
		__ret = SCLIB_REMOTE_CALL(__sysid, call, par, __off + __sz1, __off, ##__VA_ARGS__); \
		if (!SCLIB_IS_ERR(__ret)) \
			memcpy((buf), __rbuf, __sz1); \
		sclib_memory_free(&sclib_data[__sysid], __rbuf); \
	} else { \
		__ret = SCLIB_LOCAL_CALL(call, par, __dpath, (buf), ##__VA_ARGS__); \
	} \
error_mem: \
	SCLIB_ERR_RET(__ret); \
	__ret; }))

static inline const char *sclib_get_link(const char *path, int *sysid)
{
	char ch;

	if (*path == '/')
	{
		while (*(path + 1) == '/')
			path++;
		if (strncmp(path, SCLIB_STORAGE_PREFIX, sizeof(SCLIB_STORAGE_PREFIX) - 1) == 0) {
			ch = path[sizeof(SCLIB_STORAGE_PREFIX) - 1];
			if (ch == '\0' || ch == '/') {
				*sysid = SYSCALL_SYSID_STORAGE;
				return path + sizeof(SCLIB_STORAGE_PREFIX) - 1;
			}
		}
		*sysid = SYSCALL_SYSID_LOCAL;
	} else {
		*sysid = SYSCALL_SYSID_ALL;
	}
	return path;
}

#define SCLIB_PATH_CALL2(call, par, oldpath, newpath, ...) (__extension__ ({ \
	char __abspath1[PATH_MAX], *__dpath1, __abspath2[PATH_MAX], *__dpath2; \
	long __ret; \
	int __sysid, __sysid2; \
	void *__rbuf, *__off; \
	size_t __sz2, __sz1; \
	__dpath1 = sclib_get_path(__abspath1, (oldpath), &__sysid, &__sz1); \
	__dpath2 = sclib_get_path(__abspath2, (newpath), &__sysid2, &__sz2); \
	if (__sysid != __sysid2) { \
		__ret = -EINVAL; \
		goto error_mem; \
	} \
	if (__sysid != SYSCALL_SYSID_LOCAL) { \
		__rbuf = sclib_memory_alloc(&sclib_data[__sysid], __sz1 + __sz2); \
		SCLIB_MEM_RET(__rbuf, __ret); \
		memcpy(mempcpy(__rbuf, __dpath1, __sz1), __dpath2, __sz2); \
		__off = sclib_mem(__sysid, __rbuf); \
		__ret = SCLIB_REMOTE_CALL(__sysid, call, par, __off, __off + __sz1, ##__VA_ARGS__); \
		sclib_memory_free(&sclib_data[__sysid], __rbuf); \
	} else { \
		__ret = SCLIB_LOCAL_CALL(call, par, __dpath1, __dpath2, ##__VA_ARGS__); \
	} \
error_mem: \
	SCLIB_ERR_RET(__ret); \
	__ret; }))

#define SCLIB_LOCAL_CALL(call, num, ...) (__extension__ ({ \
	INTERNAL_SYSCALL_DECL(__err); \
	long __retval = INTERNAL_SYSCALL(call, __err, num, ##__VA_ARGS__); \
	if (INTERNAL_SYSCALL_ERROR_P(__retval, __err)) \
		__retval = -INTERNAL_SYSCALL_ERRNO(__retval, __err); \
	__retval; }))

#define SCLIB_ALL_SIMPLE_CALL(call, num, ...) (__extension__ ({				\
	void *__pos[SYSCALL_SYSIDS];											\
	long __lret, __rret;													\
	size_t __i;																\
	for (__i = 0; __i < SYSCALL_SYSIDS; __i++) {							\
		__pos[__i] =														\
			SCLIB_REMOTE_CALL_ASYNC(__i, call, num, ##__VA_ARGS__);			\
	}																		\
	__lret = SCLIB_LOCAL_CALL(call, num, ##__VA_ARGS__);					\
	for (__i = 0; __i < SYSCALL_SYSIDS; __i++) {							\
		__rret = SCLIB_REMOTE_CALL_RESULT(__i, call, __pos[__i]);			\
		if (SCLIB_IS_ERR(__rret))											\
			__lret = __rret;												\
	}																		\
	__lret; }))

#define __SCLIB_REMOTE_ARGS0(e)
#define __SCLIB_REMOTE_ARGS1(e, x0)	(e[0] = (long) (x0))
#define __SCLIB_REMOTE_ARGS2(e, x0, x1)	\
	__SCLIB_REMOTE_ARGS1(e, x0); e[1] = (long) (x1);
#define __SCLIB_REMOTE_ARGS3(e, x0, x1, x2)	\
	__SCLIB_REMOTE_ARGS2(e, x0, x1); e[2] = (long) (x2);
#define __SCLIB_REMOTE_ARGS4(e, x0, x1, x2, x3)	\
	__SCLIB_REMOTE_ARGS3(e, x0, x1, x2); e[3] = (long) (x3);
#define __SCLIB_REMOTE_ARGS5(e, x0, x1, x2, x3, x4)	\
	__SCLIB_REMOTE_ARGS4(e, x0, x1, x2, x3); e[4] = (long) (x4);
#define __SCLIB_REMOTE_ARGS6(e, x0, x1, x2, x3, x4, x5)	\
	__SCLIB_REMOTE_ARGS5(e, x0, x1, x2, x3, x4); e[5] = (long) (x5);

#define __SCLIB_REMOTE_CALL(rwidth, sysid, call, num, ...) (__extension__ ({ \
	syscall_entry_t *__entry = sclib_get_entry(&sclib_data[sysid]); \
	__SCLIB_REMOTE_ARGS##num(__entry->args, ##__VA_ARGS__); \
	__entry->pd = THREAD_SELF; \
	__entry->task_id = sclib_thread.task_id; \
	__entry->seq_num = sclib_thread.seq_num++; \
	__entry->id = __NRR_##call; \
	__entry->signal = 0; \
	sclib_put_entry(sysid, __entry); \
	sclib_get_result_##rwidth(&sclib_data[sysid].buffer->page, sysid, __entry); }))

#define SCLIB_REMOTE_CALL_DW(...)	\
	__SCLIB_REMOTE_CALL(dw, ##__VA_ARGS__)

#define SCLIB_REMOTE_CALL(...)	\
	__SCLIB_REMOTE_CALL(sw, ##__VA_ARGS__)

#define SCLIB_REMOTE_CALL_ASYNC(sysid, call, num, ...) (__extension__ ({ \
	syscall_entry_t *__entry = sclib_get_entry(&sclib_data[sysid]); \
	__SCLIB_REMOTE_ARGS##num(__entry->args, ##__VA_ARGS__); \
	__entry->pd = THREAD_SELF; \
	__entry->task_id = sclib_thread.task_id; \
	__entry->seq_num = sclib_thread.seq_num++; \
	__entry->id = __NRR_##call;	\
	__entry->signal = 0; \
	sclib_put_entry(sysid, __entry); \
	__entry; }))

#define __SCLIB_REMOTE_CALL_RESULT(rwidth, sysid, call, __entry_ptr)	\
	sclib_get_result_##rwidth(&sclib_data[sysid].buffer->page, sysid, __entry_ptr)

#define SCLIB_REMOTE_CALL_RESULT_DW(sysid, call, __entry_ptr)	\
	__SCLIB_REMOTE_CALL_RESULT(dw, sysid, call, __entry_ptr)

#define SCLIB_REMOTE_CALL_RESULT(sysid, call, __entry_ptr)	\
	__SCLIB_REMOTE_CALL_RESULT(sw, sysid, call, __entry_ptr)

#define SCLIB_SYSID_CALL(sysid, ...) (__extension__ ({ \
	long __r; \
	if ((sysid) != SYSCALL_SYSID_LOCAL) \
		__r = SCLIB_REMOTE_CALL(sysid, __VA_ARGS__); \
	else \
		__r = SCLIB_LOCAL_CALL(__VA_ARGS__); \
	__r; }))

#define SCLIB_SYSID_CALL_BUFFER(sysid, call, par, arg0, argb, ...) (__extension__ ({ \
	long __r; \
	if ((sysid) != SYSCALL_SYSID_LOCAL) \
		__r = SCLIB_REMOTE_CALL(sysid, call, par, arg0, sclib_mem(sysid, argb), ##__VA_ARGS__); \
	else \
		__r = SCLIB_LOCAL_CALL(call, par, arg0, argb, ##__VA_ARGS__); \
	__r; }))

#define SCLIB_FILE_TABLE_LENGTH		1024
#define SCLIB_FD_EXEC				0x01
#define SCLIB_FD_TRAN				0x02

#ifdef SYSCALL_DEBUG

# define SCLIB_STRACE_DEBUG(fmt, ...) (__extension__ ({ \
	char __buf[64];														\
	size_t __num = snprintf(__buf, sizeof(__buf), (fmt), ##__VA_ARGS__);	\
	if (__num > sizeof(__buf) - 1)											\
		__num = sizeof(__buf) - 1;											\
	SCLIB_LOCAL_CALL(write, 3, -1, __buf, __num);							\
}))

# define SCLIB_LOCK_CHECK_INIT	\
	size_t __lock_check_counter = 500000;

# define SCLIB_LOCK_CHECK_STEP					do {		\
	if (--__lock_check_counter == 0) {						\
		fprintf(stderr, "LOCKUP BUG: %s\n", __FUNCTION__);	\
		SCLIB_STRACE_DEBUG("LOCKUP BUG: %s\n", __FUNCTION__);	\
		_exit(1);											\
	}														\
} while (0);

#else

# define SCLIB_STRACE_DEBUG(fmt, ...)
# define SCLIB_LOCK_CHECK_INIT
# define SCLIB_LOCK_CHECK_STEP

#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef int16_t sclib_fd_t;

typedef struct sclib_file_entry_s {
	sclib_fd_t dfd;
	sclib_fd_t aux[SYSCALL_SYSIDS];
	uint8_t ectl_doms;
	int8_t sysid;
	uint8_t flags;
	uint8_t _pad;
	uint32_t counter;
	uint32_t flags_counter;
} sclib_file_entry_t;

typedef struct sclib_file_table_s {
	sclib_file_entry_t fds[SCLIB_FILE_TABLE_LENGTH];
	unsigned long bitmap[SCLIB_FILE_TABLE_LENGTH / (sizeof(long) * 8)];
	long fd[SYSCALL_SYSIDS];
	char curdir[PATH_MAX];
	size_t curdir_size;
} sclib_file_table_t;

void sclib_file_replace(sclib_file_table_t *file, long fd, long dfd, int sysid,
	sclib_fd_t *aux);
libc_hidden_proto(sclib_file_replace)

long sclib_file_close(sclib_file_table_t *file, long fd);
libc_hidden_proto(sclib_file_close)

static inline long sclib_bitmap_find(unsigned long *bitmap, size_t size,
	size_t start)
{
	unsigned long val;
	size_t i, shift, mask = (sizeof(long) * 8) - 1;

	i = (start & ~mask) / 8;
	shift = start & mask;
	if (!__builtin_constant_p(start) || shift) {
		val = (*(unsigned long *) ((char *) bitmap + i)) & (ULONG_MAX << shift);
		if (val != 0)
			return __builtin_ctzl(val) + i * 8;
		i += sizeof(long);
	}

	for (; i != size; i += sizeof(long)) {
		val = *(unsigned long *) ((char *) bitmap + i);
		if (val != 0)
			return __builtin_ctzl(val) + i * 8;
	}
	return -EMFILE;
}

static inline void sclib_bitmap_toggle(unsigned long *bitmap, size_t pos)
{
	size_t i = pos / (sizeof(long) * 8);
	size_t shift = pos % (sizeof(long) * 8);
	__sync_fetch_and_xor(bitmap + i, 1UL << shift);
}

static inline bool sclib_replace_lock_fd(sclib_file_table_t *file, long fd)
{
	uint32_t val;
	SCLIB_LOCK_CHECK_INIT
	do {
		SCLIB_LOCK_CHECK_STEP
		val = __sync_val_compare_and_swap(&file->fds[fd].counter, 3, 1);
		if (val == 0) {
			if (__sync_bool_compare_and_swap(&file->fds[fd].counter, 0, 1))
				return false;
		}
	} while (val != 3);

	return true;
}

static inline void sclib_replace_unlock_fd(sclib_file_table_t *file, long fd)
{
	__sync_fetch_and_add(&file->fds[fd].counter, 2); /* Counter = 3 (ready) */
}

static inline bool sclib_incref_fd(sclib_file_table_t *file, long fd)
{
	uint32_t val;

	/* Increment if file is in ready state */
	do {
		val = file->fds[fd].counter;
		if (val <= 2)
			return false;
	} while (!__sync_bool_compare_and_swap(&file->fds[fd].counter, val, val + 1));
	return true;
}

static inline void sclib_putref_fd(sclib_file_table_t *file, long fd, uint32_t step)
{
	if (__sync_sub_and_fetch(&file->fds[fd].counter, step) == 2) {
		sclib_file_close(file, fd);
		file->fds[fd].dfd = -1;
		sclib_bitmap_toggle(file->bitmap, fd);
		__sync_fetch_and_sub(&file->fds[fd].counter, 2);
	}
}

static inline void sclib_write_lock_fd_flags(sclib_file_table_t *file, long fd)
{
	SCLIB_LOCK_CHECK_INIT
	/* Move from ready state (1) to write state (0) */
	while (!__sync_bool_compare_and_swap(&file->fds[fd].flags_counter, 1, 0)) {
		SCLIB_LOCK_CHECK_STEP
	}
}

static inline void sclib_write_unlock_fd_flags(sclib_file_table_t *file, long fd)
{
	__sync_fetch_and_add(&file->fds[fd].flags_counter, 1);
}

static inline void sclib_read_lock_fd_flags(sclib_file_table_t *file, long fd)
{
	uint32_t val;
	SCLIB_LOCK_CHECK_INIT

	/* Move from ready state (1) to read state (> 1) */
	do {
		SCLIB_LOCK_CHECK_STEP
		val = file->fds[fd].flags_counter;
	} while (val == 0 || !__sync_bool_compare_and_swap(&file->fds[fd].flags_counter, val, val + 1));
}

static inline void sclib_read_unlock_fd_flags(sclib_file_table_t *file, long fd)
{
	__sync_fetch_and_sub(&file->fds[fd].flags_counter, 1);
}

static inline long sclib_file_add(sclib_file_table_t *file,
	unsigned long start_fd)
{
	long fd;
	SCLIB_LOCK_CHECK_INIT

	do {
		SCLIB_LOCK_CHECK_STEP
		/* Optimistic search */
		fd = sclib_bitmap_find(file->bitmap, sizeof(file->bitmap), start_fd);
		if (unlikely(fd < 0))
			return fd;
	} while (!__sync_bool_compare_and_swap(&file->fds[fd].counter, 0, 1));
	sclib_bitmap_toggle(file->bitmap, fd);
	return fd;
}

static inline sclib_fd_t *sclib_file_aux(sclib_file_table_t *file, long fd)
{
	return file->fds[fd].aux;
}

static inline void sclib_file_add_fail(sclib_file_table_t *file, long fd)
{
	sclib_bitmap_toggle(file->bitmap, fd); /* Cancel allocation */
	__sync_fetch_and_sub(&file->fds[fd].counter, 1); /* Counter = 0 (free) */
}

static inline void sclib_file_add_ok(sclib_file_table_t *file, long fd, long dfd, int sysid, uint8_t flags, uint8_t ectl_doms)
{
	file->fds[fd].dfd = dfd;
	file->fds[fd].sysid = sysid;
	file->fds[fd].flags = flags;
	file->fds[fd].ectl_doms = ectl_doms;
	__sync_fetch_and_add(&file->fds[fd].counter, 2); /* Counter = 3 (ready) */
}

static inline void sclib_file_add_done(sclib_file_table_t *file, long fd, long dfd, int sysid, uint8_t flags, uint8_t ectl_doms)
{
	if (SCLIB_IS_ERR(dfd)) {
		sclib_file_add_fail(file, fd);
	} else {
		sclib_file_add_ok(file, fd, dfd, sysid, flags, ectl_doms);
	}
}

static inline long sclib_file_get(sclib_file_table_t *file, long fd, int sysid)
{
	int id;
	long dfd;

	if (unlikely((unsigned long) fd >= SCLIB_FILE_TABLE_LENGTH
			|| !sclib_incref_fd(file, fd)))
		return -EBADF;
	id = file->fds[fd].sysid;
	dfd = file->fds[fd].dfd;
	if (unlikely(sysid != id)) {
		sclib_putref_fd(file, fd, 1);
		return -EINVAL;
	}
	return dfd;
}

static inline long sclib_file_getid(sclib_file_table_t *file, long fd, int *sysid)
{
	long dfd;

	*sysid = SYSCALL_SYSID_LOCAL;
	if (unlikely((unsigned long) fd >= SCLIB_FILE_TABLE_LENGTH
			|| !sclib_incref_fd(file, fd)))
		return -EBADF;
	dfd = file->fds[fd].dfd;
	*sysid = file->fds[fd].sysid;
	return dfd;
}

static inline long sclib_file_touch(sclib_file_table_t *file, long fd, int *sysid)
{
	long dfd;

	dfd = file->fds[fd].dfd;
	*sysid = file->fds[fd].sysid;
	return dfd;
}

static inline void sclib_file_put(sclib_file_table_t *file, long fd)
{
	sclib_putref_fd(file, fd, 1);
}

static inline void sclib_file_release(sclib_file_table_t *file, long fd)
{
	sclib_putref_fd(file, fd, 2);
}

static inline long sclib_file_reverse_lookup(sclib_file_table_t *file, unsigned long dfd)
{
	size_t fd;
	int found = 0;

	for (fd = 0; fd < SCLIB_FILE_TABLE_LENGTH; fd++) {
		if (!sclib_incref_fd(file, fd))
			continue;
		if ((unsigned long) file->fds[fd].dfd == dfd)
			found = 1;
		sclib_putref_fd(file, fd, 1);
		if (found)
			return fd;
	}
	return -EINVAL;
}

struct sclib_memory_list_s;
typedef struct sclib_memory_list_s sclib_memory_list_t;

struct sclib_memory_list_s {
	sclib_memory_list_t *pred;
	sclib_memory_list_t *succ;
};

typedef struct sclib_buffer_s {
	syscall_wake_page_t wake_page;
	syscall_page_t page;
	char data[0];
} sclib_buffer_t;

typedef struct sclib_data_s {
	sclib_buffer_t *buffer;
	long memoff;
	sclib_memory_list_t memory;
	char *map_start;
	char *map_end;
	unsigned long map_pos;
	long sysid;
} sclib_data_t;

typedef struct sclib_thread_data {
	long efd[SYSCALL_SYSIDS+1];
	unsigned int task_id;
	unsigned int seq_num;
} sclib_thread_data_t;

extern sclib_data_t sclib_data[SYSCALL_SYSIDS];
libc_hidden_proto(sclib_data)

typedef struct sclib_miscdata_s {
	long membase;
	long domfd;
} sclib_miscdata_t;

extern sclib_miscdata_t sclib_miscdata[SYSCALL_SYSIDS];
libc_hidden_proto(sclib_miscdata)

extern sclib_file_table_t sclib_file;
libc_hidden_proto(sclib_file)

#ifdef __UCLIBC_HAS_TLS__
extern __thread sclib_thread_data_t sclib_thread;
#else
# error "Need TLS support for SCLIB thread data"
#endif

void *sclib_memory_alloc(sclib_data_t *data, size_t size);
libc_hidden_proto(sclib_memory_alloc)

void sclib_memory_free(sclib_data_t *data, void *addr);
libc_hidden_proto(sclib_memory_free)

ssize_t sclib_iovec_length(const struct iovec *iov, size_t count);
libc_hidden_proto(sclib_iovec_length)

void *sclib_copy_from_iovec(void *to, struct sclib_iovc *from, size_t count);
libc_hidden_proto(sclib_copy_from_iovec)

void sclib_copy_to_iovec(struct sclib_iovc *to, const void *from, size_t length);
libc_hidden_proto(sclib_copy_to_iovec)

struct msghdr *sclib_init_msghdr(struct msghdr *to, const struct msghdr *from,
								 size_t total_iovlen, struct msghdr *rto);
libc_hidden_proto(sclib_init_msghdr)

void sclib_copy_from_msghdr(struct msghdr *to, const struct msghdr *msg,
							 size_t total_iovlen);
libc_hidden_proto(sclib_copy_from_msghdr)

void sclib_copy_to_msghdr(struct msghdr *msg, const struct msghdr *from,
						size_t length, size_t total_iovlen,
						size_t controllen, size_t namelen);
libc_hidden_proto(sclib_copy_to_msghdr)

long sclib_copy_file(long in_dfd, __off_t *in_off, long out_dfd, __off_t *out_off, size_t len, int in_sysid, int out_sysid);
libc_hidden_proto(sclib_copy_file)

long sclib_copy64_file(long in_dfd, __off64_t *in_off, long out_dfd, __off64_t *out_off, size_t len, int in_sysid, int out_sysid);
libc_hidden_proto(sclib_copy64_file)

static inline syscall_entry_t *sclib_get_entry(sclib_data_t *data)
{
	SCLIB_LOCK_CHECK_INIT
	syscall_page_t *page = &data->buffer->page;
	size_t eidx;

	while (1) {
		SCLIB_LOCK_CHECK_STEP
		eidx = syscall_stack_pop(page->next, &page->free_top, SYSCALL_MAX_ENTRIES);
		if (unlikely(eidx == SYSCALL_ERROR_ENTRY)) {
			fprintf(stderr, "ERROR: fatal (free) dequeue error!\n");
			_exit(1);
		}
		if (eidx != SYSCALL_NULL_ENTRY)
			return &page->entry[eidx];
		sched_yield();
	}
}

static inline void sclib_put_entry(int sysid, syscall_entry_t *entry)
{
	uint64_t running_threads;
	syscall_wake_page_t *wake_page = &sclib_data[sysid].buffer->wake_page;
	syscall_page_t *page = &sclib_data[sysid].buffer->page;

	syscall_stack_push(page->next, &page->alloc_top, (size_t) (entry - page->entry));
	/* Notify the other side if necessary */
	running_threads = wake_page->running_threads;
	if ((running_threads & (SYSCALL_WAKE_REQUESTED | SYSCALL_WAKE_IN_PROGRESS)) == SYSCALL_WAKE_REQUESTED)
		SCLIB_LOCAL_CALL(ioctl, 3, sclib_miscdata[sysid].domfd, SYSCALL_DRIVER_IOCTL_WAKE, 0);
}

static inline void sclib_wait_efd(struct syscall_efd *param, long efd)
{
	uint64_t val;
	size_t efd_num;

	efd_num = param->efd_num;
	if (efd_num == 0)
		return;
	if ((ssize_t) efd_num < 0) {
		efd_num = SCLIB_LOCAL_CALL(syscall_service_notify, 1, param);
		if (efd_num == 0)
			return;
	}

	do {
		if (SCLIB_LOCAL_CALL(read, 3, efd, &val, sizeof(uint64_t)) == sizeof(uint64_t))
			efd_num--;
	} while (efd_num != 0);
}

#define __SCLIB_DECLARE_GET_RESULT(rwidth, _type)						\
static inline _type sclib_get_result_##rwidth(syscall_page_t *page,		\
			int sysid, syscall_entry_t *entry)							\
{																		\
	_type ret;															\
	__sclib_schedule(sysid, entry);										\
	ret  = syscall_entry_result_##rwidth(entry);						\
	syscall_stack_push(page->next, &page->free_top,						\
		(size_t) (entry - page->entry));								\
	return ret;															\
}

__SCLIB_DECLARE_GET_RESULT(sw, long)
__SCLIB_DECLARE_GET_RESULT(dw, syscall_sdw_t)

static inline void *sclib_mem(int sysid, void *addr)
{
	return (char *) addr + sclib_data[sysid].memoff;
}

static inline void *sclib_usermem(int sysid, void *addr)
{
	return (char *) addr - sclib_data[sysid].memoff;
}

#ifdef __cplusplus
}
#endif

#endif /* !_SCLIB_PUBLIC_H */
