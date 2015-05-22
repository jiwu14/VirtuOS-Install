/*
 * Copyright (C) 2012 Ruslan Nikolaev <rnikola@vt.edu>
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#define __FORCE_GLIBC
#include <features.h>
#include <errno.h>
#include <syscall.h>
#include <sys/socket.h>
#include <string.h>

#include <bits/sclib.h>
#include <bits/sclib_syscalls.h>

#define MAX_SOCKADDR_LEN	(1024 * 4096)

#ifdef __NR_socketcall
extern int __socketcall(int call, unsigned long *args) attribute_hidden;

/* Various socketcall numbers */
#define SYS_SOCKET      1
#define SYS_BIND        2
#define SYS_CONNECT     3
#define SYS_LISTEN      4
#define SYS_ACCEPT      5
#define SYS_GETSOCKNAME 6
#define SYS_GETPEERNAME 7
#define SYS_SOCKETPAIR  8
#define SYS_SEND        9
#define SYS_RECV        10
#define SYS_SENDTO      11
#define SYS_RECVFROM    12
#define SYS_SHUTDOWN    13
#define SYS_SETSOCKOPT  14
#define SYS_GETSOCKOPT  15
#define SYS_SENDMSG     16
#define SYS_RECVMSG     17
#define SYS_ACCEPT4     18
#endif

#ifdef __UCLIBC_HAS_THREADS_NATIVE__
#include <sysdep-cancel.h>
#include <pthreadP.h>
#else
#define SINGLE_THREAD_P 1
#endif

#ifdef L_accept
extern __typeof(accept) __libc_accept;
#ifdef __NR_accept
static int __sys_accept(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
	int sysid;
	long new_fd, new_dfd, dfd;

	dfd = sclib_file_getid(&sclib_file, fd, &sysid);
	SCLIB_ERR_RET(dfd);
	new_fd = sclib_file_add(&sclib_file, 0);
	SCLIB_VAL_RET(new_fd, new_dfd);

	if (sysid != SYSCALL_SYSID_LOCAL) {
		size_t len = MAX_SOCKADDR_LEN;
		syscall_udw_t dwret;
		void *mem = mem, *raddr = NULL;

		if (addr != NULL) {
			if ((size_t) *addrlen < len)
				len = *addrlen;
			mem = sclib_memory_alloc(&sclib_data[sysid], len);
			SCLIB_MEM_RET(mem, new_dfd);
			raddr = sclib_mem(sysid, mem);
		}
		/* len is both input and output (upper word) */
		dwret = SCLIB_REMOTE_CALL_DW(sysid, accept, 3, dfd, len, raddr);
		new_dfd = syscall_result_lower(dwret);
		if (addr != NULL) {
			if (!SCLIB_IS_ERR(new_dfd)) {
				size_t retlen = syscall_result_upper(dwret);
				memcpy(addr, mem, MIN(len, retlen));
				*addrlen = retlen;
			}
			sclib_memory_free(&sclib_data[sysid], mem);
		}
	} else {
		new_dfd = SCLIB_LOCAL_CALL(accept, 3, dfd, addr, addrlen);
	}

error_mem:
	sclib_file_add_done(&sclib_file, new_fd, new_dfd, sysid, 0, 0);
error_val:
	sclib_file_put(&sclib_file, fd);

	SCLIB_ERR_RET(new_dfd);
	return new_fd;
}

int __libc_accept(int s, struct sockaddr *addr, socklen_t * addrlen)
{
	if (SINGLE_THREAD_P)
		return __sys_accept(s, addr, addrlen);

#ifdef __UCLIBC_HAS_THREADS_NATIVE__
	int oldtype = LIBC_CANCEL_ASYNC ();
	int result = __sys_accept(s, addr, addrlen);
	LIBC_CANCEL_RESET (oldtype);
	return result;
#endif
}
#elif defined(__NR_socketcall)
int __libc_accept(int s, struct sockaddr *addr, socklen_t * addrlen)
{
	unsigned long args[3];

	args[0] = s;
	args[1] = (unsigned long) addr;
	args[2] = (unsigned long) addrlen;

	if (SINGLE_THREAD_P)
		return __socketcall(SYS_ACCEPT, args);

#ifdef __UCLIBC_HAS_THREADS_NATIVE__
	int oldtype = LIBC_CANCEL_ASYNC ();
	int result = __socketcall(SYS_ACCEPT, args);
	LIBC_CANCEL_RESET (oldtype);
	return result;
#endif
}
#endif
weak_alias(__libc_accept,accept)
libc_hidden_weak(accept)
#endif

#ifdef L_accept4
#ifdef __NR_accept4
static int __sys_accept4(int fd, struct sockaddr *addr, socklen_t *addrlen,
						 int flags)
{
	int sysid;
	long new_fd, new_dfd, dfd = sclib_file_getid(&sclib_file, fd, &sysid);

	SCLIB_ERR_RET(dfd);
	new_fd = sclib_file_add(&sclib_file, 0);
	SCLIB_VAL_RET(new_fd, new_dfd);

	if (sysid != SYSCALL_SYSID_LOCAL) {
		size_t len = MAX_SOCKADDR_LEN;
		syscall_udw_t dwret;
		void *mem = mem, *raddr = NULL;

		if (addr != NULL) {
			if ((size_t) *addrlen < len)
				len = *addrlen;
			mem = sclib_memory_alloc(&sclib_data[sysid], len);
			SCLIB_MEM_RET(mem, new_dfd);
			raddr = sclib_mem(sysid, mem);
		}
		dwret = SCLIB_REMOTE_CALL_DW(sysid, accept4, 4, dfd, len, raddr, flags);
		new_dfd = syscall_result_lower(dwret);
		if (addr != NULL) {
			if (!SCLIB_IS_ERR(new_dfd)) {
				size_t retlen = syscall_result_upper(dwret);
				memcpy(addr, mem, MIN(len, retlen));
				*addrlen = retlen;
			}
			sclib_memory_free(&sclib_data[sysid], mem);
		}
	} else {
		new_dfd = SCLIB_LOCAL_CALL(accept4, 4, dfd, addr, addrlen, flags);
	}

error_mem:
	if (SCLIB_IS_ERR(new_dfd)) {
		sclib_file_add_fail(&sclib_file, new_fd);
	} else {
		uint8_t new_dfd_flags = 0;
		if (flags & SOCK_CLOEXEC)
			new_dfd_flags |= SCLIB_FD_EXEC;
		sclib_file_add_ok(&sclib_file, new_fd, new_dfd, sysid, new_dfd_flags, 0);
	}
error_val:
	sclib_file_put(&sclib_file, fd);

	SCLIB_ERR_RET(new_dfd);
	return new_fd;
}

int accept4(int fd, struct sockaddr *addr, socklen_t * addrlen, int flags)
{
	if (SINGLE_THREAD_P)
		return __sys_accept4(fd, addr, addrlen, flags);
#ifdef __UCLIBC_HAS_THREADS_NATIVE__
	else {
		int oldtype = LIBC_CANCEL_ASYNC ();
		int result = __sys_accept4(fd, addr, addrlen, flags);
		LIBC_CANCEL_RESET (oldtype);
		return result;
	}
#endif
}
#elif defined(__NR_socketcall)
int accept4(int fd, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
	unsigned long args[4];

	args[0] = fd;
	args[1] = (unsigned long) addr;
	args[2] = (unsigned long) addrlen;
	args[3] = flags;
	if (SINGLE_THREAD_P)
		return __socketcall(SYS_ACCEPT4, args);
#ifdef __UCLIBC_HAS_THREADS_NATIVE__
	else {
		int oldtype = LIBC_CANCEL_ASYNC ();
		int result = __socketcall(SYS_ACCEPT4, args);
		LIBC_CANCEL_RESET (oldtype);
		return result;
	}
#endif
}
#endif
#endif

#ifdef L_bind
#ifdef __NR_bind
int bind(int fd, const struct sockaddr *myaddr, socklen_t addrlen)
{
	int sysid;
	long err, dfd = sclib_file_getid(&sclib_file, fd, &sysid);

	SCLIB_ERR_RET(dfd);
	if (sysid != SYSCALL_SYSID_LOCAL) {
		void *mem = sclib_memory_alloc(&sclib_data[sysid], addrlen);

		SCLIB_MEM_RET(mem, err);
		mem = memcpy(mem, myaddr, addrlen);
		err = SCLIB_REMOTE_CALL(sysid, bind, 3, dfd, sclib_mem(sysid, mem), addrlen);
		sclib_memory_free(&sclib_data[sysid], mem);
	} else {
		err = SCLIB_LOCAL_CALL(bind, 3, dfd, myaddr, addrlen);
	}

error_mem:
	sclib_file_put(&sclib_file, fd);
	SCLIB_ERR_RET(err);
	return err;
}

#elif defined(__NR_socketcall)
int bind(int sockfd, const struct sockaddr *myaddr, socklen_t addrlen)
{
	unsigned long args[3];

	args[0] = sockfd;
	args[1] = (unsigned long) myaddr;
	args[2] = addrlen;
	return __socketcall(SYS_BIND, args);
}
#endif
libc_hidden_def(bind)
#endif

#ifdef L_connect
extern __typeof(connect) __libc_connect;
#ifdef __NR_connect
static int __sys_connect(int fd, const struct sockaddr *saddr, socklen_t addrlen)
{
	int sysid;
	long err, dfd;

	dfd = sclib_file_getid(&sclib_file, fd, &sysid);
	SCLIB_ERR_RET(dfd);

	if (sysid != SYSCALL_SYSID_LOCAL) {
		void *mem = sclib_memory_alloc(&sclib_data[sysid], addrlen);

		SCLIB_MEM_RET(mem, err);
		mem = memcpy(mem, saddr, addrlen);
		err = SCLIB_REMOTE_CALL(sysid, connect, 3, dfd, sclib_mem(sysid, mem), addrlen);
		sclib_memory_free(&sclib_data[sysid], mem);
	} else {
		err = SCLIB_LOCAL_CALL(connect, 3, dfd, saddr, addrlen);
	}

error_mem:
	sclib_file_put(&sclib_file, fd);
	SCLIB_ERR_RET(err);
	return err;
}

int __libc_connect(int sockfd, const struct sockaddr *saddr, socklen_t addrlen)
{
	if (SINGLE_THREAD_P)
		return __sys_connect(sockfd, saddr, addrlen);

#ifdef __UCLIBC_HAS_THREADS_NATIVE__
	int oldtype = LIBC_CANCEL_ASYNC ();
	int result = __sys_connect(sockfd, saddr, addrlen);
	LIBC_CANCEL_RESET (oldtype);
	return result;
#endif
}
#elif defined(__NR_socketcall)
int __libc_connect(int sockfd, const struct sockaddr *saddr, socklen_t addrlen)
{
	unsigned long args[3];

	args[0] = sockfd;
	args[1] = (unsigned long) saddr;
	args[2] = addrlen;

	if (SINGLE_THREAD_P)
		return __socketcall(SYS_CONNECT, args);

#ifdef __UCLIBC_HAS_THREADS_NATIVE__
	int oldtype = LIBC_CANCEL_ASYNC ();
	int result = __socketcall(SYS_CONNECT, args);
	LIBC_CANCEL_RESET (oldtype);
	return result;
#endif
}
#endif
weak_alias(__libc_connect,connect)
libc_hidden_weak(connect)
#endif

#ifdef L_getpeername
#ifdef __NR_getpeername

int getpeername(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
	int sysid;
	long err, dfd = sclib_file_getid(&sclib_file, fd, &sysid);

	SCLIB_ERR_RET(dfd);
	if (sysid != SYSCALL_SYSID_LOCAL) {
		size_t len = MAX_SOCKADDR_LEN;
		syscall_udw_t dwret;
		void *mem;

		if ((size_t) *addrlen < len)
			len = *addrlen;
		mem = sclib_memory_alloc(&sclib_data[sysid], len);
		SCLIB_MEM_RET(mem, err);
		dwret = SCLIB_REMOTE_CALL_DW(sysid, getpeername, 3, dfd, len, sclib_mem(sysid, mem));
		err = syscall_result_lower(dwret);
		if (!SCLIB_IS_ERR(err)) {
			size_t retlen = syscall_result_upper(dwret);
			memcpy(addr, mem, MIN(len, retlen));
			*addrlen = retlen;
		}
		sclib_memory_free(&sclib_data[sysid], mem);
	} else {
		err = SCLIB_LOCAL_CALL(getpeername, 3, dfd, addr, addrlen);
	}

error_mem:
	sclib_file_put(&sclib_file, fd);
	SCLIB_ERR_RET(err);
	return err;
}
#elif defined(__NR_socketcall)
int getpeername(int sockfd, struct sockaddr *addr, socklen_t * paddrlen)
{
	unsigned long args[3];

	args[0] = sockfd;
	args[1] = (unsigned long) addr;
	args[2] = (unsigned long) paddrlen;
	return __socketcall(SYS_GETPEERNAME, args);
}
#endif
#endif

#ifdef L_getsockname
#ifdef __NR_getsockname
int getsockname(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
	int sysid;
	long err, dfd = sclib_file_getid(&sclib_file, fd, &sysid);

	SCLIB_ERR_RET(dfd);
	if (sysid != SYSCALL_SYSID_LOCAL) {
		size_t len = MAX_SOCKADDR_LEN;
		syscall_udw_t dwret;
		void *mem;

		if ((size_t) *addrlen < len)
			len = *addrlen;
		mem = sclib_memory_alloc(&sclib_data[sysid], len);
		SCLIB_MEM_RET(mem, err);
		dwret = SCLIB_REMOTE_CALL_DW(sysid, getsockname, 3, dfd, len, sclib_mem(sysid, mem));
		err = syscall_result_lower(dwret);
		if (!SCLIB_IS_ERR(err)) {
			size_t retlen = syscall_result_upper(dwret);
			memcpy(addr, mem, MIN(len, retlen));
			*addrlen = retlen;
		}
		sclib_memory_free(&sclib_data[sysid], mem);
	} else {
		err = SCLIB_LOCAL_CALL(getsockname, 3, dfd, addr, addrlen);
	}

error_mem:
	sclib_file_put(&sclib_file, fd);
	SCLIB_ERR_RET(err);
	return err;
}

#elif defined(__NR_socketcall)
int getsockname(int sockfd, struct sockaddr *addr, socklen_t * paddrlen)
{
	unsigned long args[3];

	args[0] = sockfd;
	args[1] = (unsigned long) addr;
	args[2] = (unsigned long) paddrlen;
	return __socketcall(SYS_GETSOCKNAME, args);
}
#endif
libc_hidden_def(getsockname)
#endif

#ifdef L_getsockopt
#ifdef __NR_getsockopt
int getsockopt(int fd, int level, int optname, void *optval, socklen_t *optlen)
{
	int sysid;
	long err, dfd = sclib_file_getid(&sclib_file, fd, &sysid);

	SCLIB_ERR_RET(dfd);
	if (sysid != SYSCALL_SYSID_LOCAL) {
		size_t len = *optlen;
		syscall_udw_t dwret;
		void *mem;

		if ((size_t) *optlen < len)
			len = *optlen;
		mem = sclib_memory_alloc(&sclib_data[sysid], len);
		SCLIB_MEM_RET(mem, err);
		dwret = SCLIB_REMOTE_CALL_DW(sysid, getsockopt, 5, dfd, len, optname,
									sclib_mem(sysid, mem), level);
		err = syscall_result_lower(dwret);
		if (!SCLIB_IS_ERR(err)) {
			size_t retlen = syscall_result_upper(dwret);
			memcpy(optval, mem, MIN(len, retlen));
			*optlen = retlen;
		}
		sclib_memory_free(&sclib_data[sysid], mem);
	} else {
		err = SCLIB_LOCAL_CALL(getsockopt, 5, dfd, level, optname, optval, optlen);
	}

error_mem:
	sclib_file_put(&sclib_file, fd);
	SCLIB_ERR_RET(err);
	return err;

}

#elif defined(__NR_socketcall)
int getsockopt(int fd, int level, int optname, __ptr_t optval,
		   socklen_t * optlen)
{
	unsigned long args[5];

	args[0] = fd;
	args[1] = level;
	args[2] = optname;
	args[3] = (unsigned long) optval;
	args[4] = (unsigned long) optlen;
	return (__socketcall(SYS_GETSOCKOPT, args));
}
#endif
#endif

#ifdef L_listen
#ifdef __NR_listen

int listen(int fd, int backlog)
{
	int sysid;
	long err, dfd = sclib_file_getid(&sclib_file, fd, &sysid);

	SCLIB_ERR_RET(dfd);
	err = SCLIB_SYSID_CALL(sysid, listen, 2, dfd, backlog);
	sclib_file_put(&sclib_file, fd);
	SCLIB_ERR_RET(err);
	return err;
}

#elif defined(__NR_socketcall)
int listen(int sockfd, int backlog)
{
	unsigned long args[2];

	args[0] = sockfd;
	args[1] = backlog;
	return __socketcall(SYS_LISTEN, args);
}
#endif
libc_hidden_def(listen)
#endif

#ifdef L_recv
extern __typeof(recv) __libc_recv;
#ifdef __NR_recv
#define __NR___sys_recv __NR_recv
static
_syscall4(ssize_t, __sys_recv, int, sockfd, __ptr_t, buffer, size_t, len,
	int, flags)
ssize_t __libc_recv(int sockfd, __ptr_t buffer, size_t len, int flags)
{
	if (SINGLE_THREAD_P)
		return __sys_recv(sockfd, buffer, len, flags);

#ifdef __UCLIBC_HAS_THREADS_NATIVE__
	int oldtype = LIBC_CANCEL_ASYNC ();
	int result = __sys_recv(sockfd, buffer, len, flags);
	LIBC_CANCEL_RESET (oldtype);
	return result;
#endif
}
#elif defined(__NR_socketcall)
/* recv, recvfrom added by bir7@leland.stanford.edu */
ssize_t __libc_recv(int sockfd, __ptr_t buffer, size_t len, int flags)
{
	unsigned long args[4];

	args[0] = sockfd;
	args[1] = (unsigned long) buffer;
	args[2] = len;
	args[3] = flags;

	if (SINGLE_THREAD_P)
		return (__socketcall(SYS_RECV, args));

#ifdef __UCLIBC_HAS_THREADS_NATIVE__
	int oldtype = LIBC_CANCEL_ASYNC ();
	int result = __socketcall(SYS_RECV, args);
	LIBC_CANCEL_RESET (oldtype);
	return result;
#endif
}
#elif defined(__NR_recvfrom)
ssize_t __libc_recv(int sockfd, __ptr_t buffer, size_t len, int flags)
{
	return (recvfrom(sockfd, buffer, len, flags, NULL, NULL));
}
#endif
weak_alias(__libc_recv,recv)
libc_hidden_weak(recv)
#endif

#ifdef L_recvfrom
extern __typeof(recvfrom) __libc_recvfrom;
#ifdef __NR_recvfrom
static ssize_t __sys_recvfrom(int fd, void *buffer, size_t len, int flags,
				struct sockaddr *to, socklen_t *tolen)
{
	int sysid;
	size_t size;
	long dfd;

	dfd = sclib_file_getid(&sclib_file, fd, &sysid);
	SCLIB_ERR_RET(dfd);

	if (sysid != SYSCALL_SYSID_LOCAL) {
		size_t inlen = 0;
		size_t ret, chunk = MIN(len, SCLIB_MAX_BUFFER);
		syscall_udw_t dwret;
		void *mem, *rbuffer, *rto = NULL;

		if (to != NULL) {
			inlen = MAX_SOCKADDR_LEN;
			if ((size_t) *tolen < inlen)
				inlen = *tolen;
		}
		mem = sclib_memory_alloc(&sclib_data[sysid], chunk + inlen);
		SCLIB_MEM_RET(mem, size);
		size = 0;
		rbuffer = sclib_mem(sysid, mem);
		if (to != NULL)
			rto = (struct sockaddr *) ((char *) rbuffer + chunk);

		for (; len > chunk; len -= chunk) {
			ret = SCLIB_REMOTE_CALL(sysid, recvfrom, 6, dfd, 0, chunk, flags,
									NULL, rbuffer);
			SCLIB_VAL_RET(ret, size);
			size += ret;
			buffer = mempcpy(buffer, mem, ret);
			if (unlikely(ret < chunk))
				goto error_val;
		}
		dwret = SCLIB_REMOTE_CALL_DW(sysid, recvfrom, 6, dfd, inlen, len, flags,
									 rto, rbuffer);
		ret = syscall_result_lower(dwret);
		SCLIB_VAL_RET(ret, size);
		if (to != NULL) {
			size_t retlen = syscall_result_upper(dwret);
			memcpy(to, mem + len, MIN(inlen, retlen));
			*tolen = retlen;
		}
		size += ret;
		memcpy(buffer, mem, ret);

error_val:
		sclib_memory_free(&sclib_data[sysid], mem);
	} else {
		size = SCLIB_LOCAL_CALL(recvfrom, 6, dfd, buffer, len, flags, to, tolen);
	}

error_mem:
	sclib_file_put(&sclib_file, fd);
	SCLIB_ERR_RET(size);
	return size;
}

ssize_t __libc_recvfrom(int sockfd, __ptr_t buffer, size_t len, int flags,
		 struct sockaddr *to, socklen_t * tolen)
{
	if (SINGLE_THREAD_P)
		return __sys_recvfrom(sockfd, buffer, len, flags, to, tolen);

#ifdef __UCLIBC_HAS_THREADS_NATIVE__
	int oldtype = LIBC_CANCEL_ASYNC ();
	int result = __sys_recvfrom(sockfd, buffer, len, flags, to, tolen);
	LIBC_CANCEL_RESET (oldtype);
	return result;
#endif
}
#elif defined(__NR_socketcall)
/* recv, recvfrom added by bir7@leland.stanford.edu */
ssize_t __libc_recvfrom(int sockfd, __ptr_t buffer, size_t len, int flags,
		 struct sockaddr *to, socklen_t * tolen)
{
	unsigned long args[6];

	args[0] = sockfd;
	args[1] = (unsigned long) buffer;
	args[2] = len;
	args[3] = flags;
	args[4] = (unsigned long) to;
	args[5] = (unsigned long) tolen;

	if (SINGLE_THREAD_P)
		return (__socketcall(SYS_RECVFROM, args));

#ifdef __UCLIBC_HAS_THREADS_NATIVE__
	int oldtype = LIBC_CANCEL_ASYNC ();
	int result = __socketcall(SYS_RECVFROM, args);
	LIBC_CANCEL_RESET (oldtype);
	return result;
#endif
}
#endif
weak_alias(__libc_recvfrom,recvfrom)
libc_hidden_weak(recvfrom)
#endif

#ifdef L_recvmsg
extern __typeof(recvmsg) __libc_recvmsg;
#ifdef __NR_recvmsg

static ssize_t __sys_recvmsg(int fd, struct msghdr *msg, int flags)
{
	int sysid;
	long size, dfd;

	dfd = sclib_file_getid(&sclib_file, fd, &sysid);
	SCLIB_ERR_RET(dfd);

	if (sysid != SYSCALL_SYSID_LOCAL) {
		size_t total_iovlen;
		struct msghdr *mem, *rmsg;

		total_iovlen = sclib_iovec_length(msg->msg_iov, msg->msg_iovlen);
		SCLIB_VAL_RET(total_iovlen, size);
		if (msg->msg_namelen > MAX_SOCKADDR_LEN)
			msg->msg_namelen = MAX_SOCKADDR_LEN;
		if (msg->msg_controllen > MAX_SOCKADDR_LEN)
			msg->msg_controllen = MAX_SOCKADDR_LEN;
		mem = sclib_memory_alloc(&sclib_data[sysid], sizeof(struct msghdr) +
			   sizeof(struct iovec) + total_iovlen +
			   msg->msg_controllen + msg->msg_namelen);
		SCLIB_MEM_RET(mem, size);
		rmsg = sclib_init_msghdr(mem, msg, total_iovlen, sclib_mem(sysid, mem));
		size = SCLIB_REMOTE_CALL(sysid, recvmsg, 3, dfd, rmsg, flags);
		if (!SCLIB_IS_ERR(size)) {
			sclib_copy_to_msghdr(msg, mem, size, total_iovlen,
								 mem->msg_controllen, mem->msg_namelen);
		}
		sclib_memory_free(&sclib_data[sysid], mem);
	} else {
		size = SCLIB_LOCAL_CALL(recvmsg, 3, dfd, msg, flags);
		if (!SCLIB_IS_ERR(size) && msg->msg_controllen >= CMSG_ALIGN(sizeof(struct cmsghdr)) + sizeof(int)) {
			struct cmsghdr *cmsg = (struct cmsghdr *) msg->msg_control;

			/* Convert file descriptors */
			if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
				int *fds = (int *) CMSG_DATA(cmsg);
				size_t i, n;

				n = (cmsg->cmsg_len - CMSG_ALIGN(sizeof(struct cmsghdr))) / sizeof(int);
				for (i = 0; i != n; i++) {
					long mfd;
					mfd = sclib_file_add(&sclib_file, 0);
					if (mfd < 0) {
						size = mfd;
						while (n != i) { /* Rollback remaining files */
							--n;
							SCLIB_LOCAL_CALL(close, 1, fds[n]);
						}
						while (i != 0) { /* Rollback added file */
							--i;
							__internal_sys_close(fds[i]);
						}
						goto error_val;
					}
					sclib_file_add_ok(&sclib_file, mfd, fds[i], SYSCALL_SYSID_LOCAL, 0, 0);
					fds[i] = mfd;
				}
			}
		}
	}

error_mem:
error_val:
	sclib_file_put(&sclib_file, fd);
	SCLIB_ERR_RET(size);
	return size;
}

ssize_t __libc_recvmsg(int sockfd, struct msghdr *msg, int flags)
{
	if (SINGLE_THREAD_P)
		return __sys_recvmsg(sockfd, msg, flags);

#ifdef __UCLIBC_HAS_THREADS_NATIVE__
	int oldtype = LIBC_CANCEL_ASYNC ();
	int result = __sys_recvmsg(sockfd, msg, flags);
	LIBC_CANCEL_RESET (oldtype);
	return result;
#endif
}
#elif defined(__NR_socketcall)
ssize_t __libc_recvmsg(int sockfd, struct msghdr *msg, int flags)
{
	unsigned long args[3];

	args[0] = sockfd;
	args[1] = (unsigned long) msg;
	args[2] = flags;

	if (SINGLE_THREAD_P)
		return (__socketcall(SYS_RECVMSG, args));

#ifdef __UCLIBC_HAS_THREADS_NATIVE__
	int oldtype = LIBC_CANCEL_ASYNC ();
	int result = __socketcall(SYS_RECVMSG, args);
	LIBC_CANCEL_RESET (oldtype);
	return result;
#endif
}
#endif
weak_alias(__libc_recvmsg,recvmsg)
libc_hidden_weak(recvmsg)
#endif

#ifdef L_send
extern __typeof(send) __libc_send;
#ifdef __NR_send
#define __NR___sys_send    __NR_send
static
_syscall4(ssize_t, __sys_send, int, sockfd, const void *, buffer, size_t, len, int, flags)
ssize_t __libc_send(int sockfd, const void *buffer, size_t len, int flags)
{
	if (SINGLE_THREAD_P)
		return __sys_send(sockfd, buffer, len, flags);

#ifdef __UCLIBC_HAS_THREADS_NATIVE__
	int oldtype = LIBC_CANCEL_ASYNC ();
	int result = __sys_send(sockfd, buffer, len, flags);
	LIBC_CANCEL_RESET (oldtype);
	return result;
#endif
}
#elif defined(__NR_socketcall)
/* send, sendto added by bir7@leland.stanford.edu */
ssize_t __libc_send(int sockfd, const void *buffer, size_t len, int flags)
{
	unsigned long args[4];

	args[0] = sockfd;
	args[1] = (unsigned long) buffer;
	args[2] = len;
	args[3] = flags;

	if (SINGLE_THREAD_P)
		return (__socketcall(SYS_SEND, args));

#ifdef __UCLIBC_HAS_THREADS_NATIVE__
	int oldtype = LIBC_CANCEL_ASYNC ();
	int result = __socketcall(SYS_SEND, args);
	LIBC_CANCEL_RESET (oldtype);
	return result;
#endif
}

#elif defined(__NR_sendto)
ssize_t __libc_send(int sockfd, const void *buffer, size_t len, int flags)
{
	return (sendto(sockfd, buffer, len, flags, NULL, 0));
}
#endif
weak_alias(__libc_send,send)
libc_hidden_weak(send)
#endif

#ifdef L_sendmsg
extern __typeof(sendmsg) __libc_sendmsg;
#ifdef __NR_sendmsg

static ssize_t __sys_sendmsg(int fd, const struct msghdr *msg, int flags)
{
	int sysid;
	long size, dfd;

	dfd = sclib_file_getid(&sclib_file, fd, &sysid);
	SCLIB_ERR_RET(dfd);

	if (sysid != SYSCALL_SYSID_LOCAL) {
		size_t total_iovlen;
		struct msghdr *mem, *rmsg;

		total_iovlen = sclib_iovec_length(msg->msg_iov, msg->msg_iovlen);
		SCLIB_VAL_RET(total_iovlen, size);
		mem = sclib_memory_alloc(&sclib_data[sysid], sizeof(struct msghdr) +
				sizeof(struct iovec) + total_iovlen +
				msg->msg_controllen + msg->msg_namelen);
		SCLIB_MEM_RET(mem, size);
		rmsg = sclib_init_msghdr(mem, msg, total_iovlen, sclib_mem(sysid, mem));
		sclib_copy_from_msghdr(mem, msg, total_iovlen);
		size = SCLIB_REMOTE_CALL(sysid, sendmsg, 3, dfd, rmsg, flags);
		sclib_memory_free(&sclib_data[sysid], mem);
	} else {
		struct msghdr *nmsg = (struct msghdr *) msg;
		const int *fds = NULL;
		int *nfds;
		size_t i = 0, n;

		if (msg->msg_controllen >= CMSG_ALIGN(sizeof(struct cmsghdr)) + sizeof(int)) {
			const struct cmsghdr *cmsg = (const struct cmsghdr *) msg->msg_control;
			struct cmsghdr *ncmsg;

			/* Convert file descriptors */
			if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
				nmsg = (struct msghdr *) malloc(sizeof(struct msghdr) + msg->msg_controllen);
				SCLIB_MEM_RET(nmsg, size);
				memcpy(nmsg, msg, sizeof(struct msghdr));
				ncmsg = (struct cmsghdr *) (nmsg + 1);
				nmsg->msg_control = ncmsg;
				memcpy(ncmsg, cmsg, sizeof(struct cmsghdr));
				fds = (const int *) CMSG_DATA(cmsg);
				nfds = (int *) CMSG_DATA(ncmsg);
				n = (cmsg->cmsg_len - CMSG_ALIGN(sizeof(struct cmsghdr))) / sizeof(int);
				for (; i != n; i++) {
					long mdfd;
					int msysid;
					mdfd = sclib_file_getid(&sclib_file, fds[i], &msysid);
					if (mdfd < 0 || msysid != SYSCALL_SYSID_LOCAL) {
						size = -EINVAL;
						goto error_conv;
					}
					nfds[i] = mdfd;
				}
			}
		}
		size = SCLIB_LOCAL_CALL(sendmsg, 3, dfd, nmsg, flags);
		if (fds != NULL) {
error_conv:
			while (i != 0)
				sclib_file_put(&sclib_file, fds[--i]);
			free(nmsg);
		}
	}

error_mem:
error_val:
	sclib_file_put(&sclib_file, fd);
	SCLIB_ERR_RET(size);
	return size;
}

ssize_t __libc_sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
	if (SINGLE_THREAD_P)
		return __sys_sendmsg(sockfd, msg, flags);

#ifdef __UCLIBC_HAS_THREADS_NATIVE__
	int oldtype = LIBC_CANCEL_ASYNC ();
	int result = __sys_sendmsg(sockfd, msg, flags);
	LIBC_CANCEL_RESET (oldtype);
	return result;
#endif
}
#elif defined(__NR_socketcall)
ssize_t __libc_sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
	unsigned long args[3];

	args[0] = sockfd;
	args[1] = (unsigned long) msg;
	args[2] = flags;

	if (SINGLE_THREAD_P)
		return (__socketcall(SYS_SENDMSG, args));

#ifdef __UCLIBC_HAS_THREADS_NATIVE__
	int oldtype = LIBC_CANCEL_ASYNC ();
	int result = __socketcall(SYS_SENDMSG, args);
	LIBC_CANCEL_RESET (oldtype);
	return result;
#endif
}
#endif
weak_alias(__libc_sendmsg,sendmsg)
libc_hidden_weak(sendmsg)
#endif

#ifdef L_sendto
extern __typeof(sendto) __libc_sendto;
#ifdef __NR_sendto
static ssize_t __sys_sendto(int fd, const void *buffer, size_t len, int flags,
							const struct sockaddr *to, socklen_t tolen)
{
	int sysid;
	size_t size;
	long dfd;

	dfd = sclib_file_getid(&sclib_file, fd, &sysid);
	SCLIB_ERR_RET(dfd);

	if (sysid != SYSCALL_SYSID_LOCAL) {
		size_t ret, chunk = MIN(len, SCLIB_MAX_BUFFER);
		void *rto = NULL;
		void *rbuffer, *mem = sclib_memory_alloc(&sclib_data[sysid], chunk + tolen);

		SCLIB_MEM_RET(mem, size);
		size = 0;
		rbuffer = sclib_mem(sysid, mem);
		if (to != NULL && tolen != 0)
			rto = sclib_mem(sysid, memcpy(mem + chunk, to, tolen));

		for (; len > chunk; len -= chunk) {
			memcpy(mem, buffer, chunk);
			buffer += chunk;
			ret = SCLIB_REMOTE_CALL(sysid, sendto, 6, dfd, tolen, chunk,
									flags | MSG_MORE, rto, rbuffer);
			SCLIB_VAL_RET(ret, size);
			size += ret;
			if (unlikely(ret < chunk))
				goto error_val;
		}
		memcpy(mem, buffer, len);
		ret = SCLIB_REMOTE_CALL(sysid, sendto, 6, dfd, tolen, len, flags,
								rto, rbuffer);
		SCLIB_VAL_RET(ret, size);
		size += ret;

error_val:
		sclib_memory_free(&sclib_data[sysid], mem);
	} else {
		size = SCLIB_LOCAL_CALL(sendto, 6, dfd, buffer, len, flags, to, tolen);
	}

error_mem:
	sclib_file_put(&sclib_file, fd);
	SCLIB_ERR_RET(size);
	return size;
}

ssize_t __libc_sendto(int sockfd, const void *buffer, size_t len, int flags,const struct sockaddr *to, socklen_t tolen)
{
	if (SINGLE_THREAD_P)
		return __sys_sendto(sockfd, buffer, len, flags, to, tolen);

#ifdef __UCLIBC_HAS_THREADS_NATIVE__
	int oldtype = LIBC_CANCEL_ASYNC ();
	int result = __sys_sendto(sockfd, buffer, len, flags, to, tolen);
	LIBC_CANCEL_RESET (oldtype);
	return result;
#endif
}
#elif defined(__NR_socketcall)
/* send, sendto added by bir7@leland.stanford.edu */
ssize_t __libc_sendto(int sockfd, const void *buffer, size_t len, int flags,
	   const struct sockaddr *to, socklen_t tolen)
{
	unsigned long args[6];

	args[0] = sockfd;
	args[1] = (unsigned long) buffer;
	args[2] = len;
	args[3] = flags;
	args[4] = (unsigned long) to;
	args[5] = tolen;

	if (SINGLE_THREAD_P)
		return (__socketcall(SYS_SENDTO, args));

#ifdef __UCLIBC_HAS_THREADS_NATIVE__
	int oldtype = LIBC_CANCEL_ASYNC ();
	int result = __socketcall(SYS_SENDTO, args);
	LIBC_CANCEL_RESET (oldtype);
	return result;
#endif
}
#endif
weak_alias(__libc_sendto,sendto)
libc_hidden_weak(sendto)
#endif

#ifdef L_setsockopt
#ifdef __NR_setsockopt

int setsockopt(int fd, int level, int optname, const void *optval,
			   socklen_t len)
{
	int sysid;
	long err, dfd;

	dfd = sclib_file_getid(&sclib_file, fd, &sysid);
	SCLIB_ERR_RET(dfd);

	if (sysid != SYSCALL_SYSID_LOCAL) {
		void *mem;

		mem = sclib_memory_alloc(&sclib_data[sysid], len);
		SCLIB_MEM_RET(mem, err);
		mem = memcpy(mem, optval, len);
		err = SCLIB_REMOTE_CALL(sysid, setsockopt, 5, dfd, len, optname,
								sclib_mem(sysid, mem), level);
		sclib_memory_free(&sclib_data[sysid], mem);
	} else {
		err = SCLIB_LOCAL_CALL(setsockopt, 5, dfd, level, optname, optval, len);
	}

error_mem:
	sclib_file_put(&sclib_file, fd);
	SCLIB_ERR_RET(err);
	return err;
}

#elif defined(__NR_socketcall)
/* [sg]etsockoptions by bir7@leland.stanford.edu */
int setsockopt(int fd, int level, int optname, const void *optval,
		   socklen_t optlen)
{
	unsigned long args[5];

	args[0] = fd;
	args[1] = level;
	args[2] = optname;
	args[3] = (unsigned long) optval;
	args[4] = optlen;
	return (__socketcall(SYS_SETSOCKOPT, args));
}
#endif
libc_hidden_def(setsockopt)
#endif

#ifdef L_shutdown
#ifdef __NR_shutdown
int shutdown(int fd, int how)
{
	int sysid;
	long err, dfd = sclib_file_getid(&sclib_file, fd, &sysid);

	SCLIB_ERR_RET(dfd);
	err = SCLIB_SYSID_CALL(sysid, shutdown, 2, dfd, how);
	sclib_file_put(&sclib_file, fd);
	SCLIB_ERR_RET(err);
	return err;
}

#elif defined(__NR_socketcall)
/* shutdown by bir7@leland.stanford.edu */
int shutdown(int sockfd, int how)
{
	unsigned long args[2];

	args[0] = sockfd;
	args[1] = how;
	return (__socketcall(SYS_SHUTDOWN, args));
}
#endif
#endif

#ifdef L_socket
#ifdef __NR_socket
int socket(int family, int type, int protocol)
{
	int sysid;
	long dfd, fd = sclib_file_add(&sclib_file, 0);

	SCLIB_ERR_RET(fd);
	sysid = (family != AF_UNIX) ? SYSCALL_SYSID_NETWORK : SYSCALL_SYSID_LOCAL;
	dfd = SCLIB_SYSID_CALL(sysid, socket, 3, family, type, protocol);
	if (SCLIB_IS_ERR(dfd)) {
		sclib_file_add_fail(&sclib_file, fd);
	} else {
		uint8_t dfd_flags = 0;
		if (type & SOCK_CLOEXEC)
			dfd_flags |= SCLIB_FD_EXEC;
		sclib_file_add_ok(&sclib_file, fd, dfd, sysid, dfd_flags, 0);
	}
	SCLIB_ERR_RET(dfd);
	return fd;
}

#elif defined(__NR_socketcall)
int socket(int family, int type, int protocol)
{
	unsigned long args[3];

	args[0] = family;
	args[1] = type;
	args[2] = (unsigned long) protocol;
	return __socketcall(SYS_SOCKET, args);
}
#endif
libc_hidden_def(socket)
#endif

#ifdef L_socketpair
#ifdef __NR_socketpair
int socketpair(int family, int type, int protocol, int fd[2])
{
	long ret;
	uint8_t lfd_flags;
	int lfd[2];

	/* It supposed to work only with AF_UNIX on Linux */
	ret = sclib_file_add(&sclib_file, 0);
	if (SCLIB_IS_ERR(ret))
		goto lfd_err2;
	fd[0] = ret;
	ret = sclib_file_add(&sclib_file, 0);
	if (SCLIB_IS_ERR(ret))
		goto lfd_err1;
	fd[1] = ret;
	ret = SCLIB_LOCAL_CALL(socketpair, 4, family, type, protocol, lfd);
	if (SCLIB_IS_ERR(ret)) {
		sclib_file_add_fail(&sclib_file, fd[1]);
	} else {
		lfd_flags = 0;
		if (type & SOCK_CLOEXEC)
			lfd_flags |= SCLIB_FD_EXEC;
		sclib_file_add_ok(&sclib_file, fd[1], lfd[1], SYSCALL_SYSID_LOCAL, lfd_flags, 0);
	}
lfd_err1:
	if (SCLIB_IS_ERR(ret)) {
		sclib_file_add_fail(&sclib_file, fd[0]);
	} else {
		lfd_flags = 0;
		if (type & SOCK_CLOEXEC)
			lfd_flags |= SCLIB_FD_EXEC;
		sclib_file_add_ok(&sclib_file, fd[0], lfd[0], SYSCALL_SYSID_LOCAL, lfd_flags, 0);
	}
lfd_err2:
	SCLIB_ERR_RET(ret);
	return ret;
}
#elif defined(__NR_socketcall)
int socketpair(int family, int type, int protocol, int sockvec[2])
{
	unsigned long args[4];

	args[0] = family;
	args[1] = type;
	args[2] = protocol;
	args[3] = (unsigned long) sockvec;
	return __socketcall(SYS_SOCKETPAIR, args);
}
#endif
#endif

