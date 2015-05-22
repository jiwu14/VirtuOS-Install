/* vi: set sw=4 ts=4: */
/*
 * epoll_create() / epoll_ctl() / epoll_wait() for uClibc
 *
 * Copyright (C) 2012 Ruslan Nikolaev <rnikola@vt.edu>
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <sys/epoll.h>
#ifdef __UCLIBC_HAS_THREADS_NATIVE__
# include <sysdep-cancel.h>
#else
# define SINGLE_THREAD_P 1
#endif

#include <assert.h>
#include <bits/sclib.h>

/*
 * epoll_create()
 */
#ifdef __NR_epoll_create
int epoll_create(int size)
{
	long lfd, fd = sclib_file_add(&sclib_file, 0);
	sclib_fd_t *aux;
	size_t i, n;

	SCLIB_ERR_RET(fd);
	aux = sclib_file_aux(&sclib_file, fd);
	for (n = 0; n < SYSCALL_SYSIDS; n++) {
		aux[n] = SCLIB_REMOTE_CALL(n, epoll_create, 1, size);
		if (SCLIB_IS_ERR(aux[n])) {
			lfd = aux[n];
			goto error_aux;
		}
	}
	lfd = SCLIB_LOCAL_CALL(epoll_create, 1, size);
	if (SCLIB_IS_ERR(lfd)) {
error_aux:
		for (i = 0; i < n; i++)
			SCLIB_REMOTE_CALL(i, close, 1, aux[i]);
	}
	sclib_file_add_done(&sclib_file, fd, lfd, SYSCALL_SYSID_ALL, 0, 0);
	SCLIB_ERR_RET(lfd);
	return fd;
}
#endif

/*
 * epoll_create1()
 */
#ifdef __NR_epoll_create1
int epoll_create1(int flags)
{
	long lfd, fd = sclib_file_add(&sclib_file, 0);
	sclib_fd_t *aux;
	size_t i, n;

	SCLIB_ERR_RET(fd);
	aux = sclib_file_aux(&sclib_file, fd);
	for (n = 0; n < SYSCALL_SYSIDS; n++) {
		aux[n] = SCLIB_REMOTE_CALL(n, epoll_create1, 1, flags);
		if (SCLIB_IS_ERR(aux[n])) {
			lfd = aux[n];
			goto error_aux;
		}
	}
	lfd = SCLIB_LOCAL_CALL(epoll_create1, 1, flags);
	if (SCLIB_IS_ERR(lfd)) {
error_aux:
		for (i = 0; i < n; i++)
			SCLIB_REMOTE_CALL(i, close, 1, aux[i]);
		sclib_file_add_fail(&sclib_file, fd);
	} else {
		uint8_t lfd_flags = 0;
		if (flags & EPOLL_CLOEXEC)
			lfd_flags |= SCLIB_FD_EXEC;
		sclib_file_add_ok(&sclib_file, fd, lfd, SYSCALL_SYSID_ALL, lfd_flags, 0);
	}
	SCLIB_ERR_RET(lfd);
	return fd;
}
#endif

static inline void __epoll_ctl_debug(int epfd, int op, int fd, uint32_t events, uint64_t u64)
{
    const char *str;

	if (op == EPOLL_CTL_ADD)
		str = "ECTL_ADD";
	else if (op == EPOLL_CTL_MOD)
		str = "ECTL_MOD";
	else
		str = "ECTL_DEL";
	SCLIB_STRACE_DEBUG("%s [EFD=%i, FD=%i, EVT=0x%x, 0x%llx]", str, epfd, fd, events, u64);
}

/*
 * epoll_ctl()
 */
#ifdef __NR_epoll_ctl
int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
	int sysid;
	long lepfd, dfd, ret;
	sclib_fd_t *epaux;

	//__epoll_ctl_debug(epfd, op, fd, event->events, event->data.u64);
	lepfd = sclib_file_get(&sclib_file, epfd, SYSCALL_SYSID_ALL);
	SCLIB_ERR_RET(lepfd);
	epaux = sclib_file_aux(&sclib_file, epfd);
	dfd = sclib_file_getid(&sclib_file, fd, &sysid);
	SCLIB_VAL_RET(dfd, ret);

	switch (sysid)
	{
	default:
	{
		long net_events;
		uint64_t net_data;

		__sync_fetch_and_or(&sclib_file.fds[epfd].ectl_doms, 1U << sysid);
		if (op == EPOLL_CTL_DEL) {
			net_events = 0;
			net_data = 0;
		} else {
			net_events = event->events;
			net_data = event->data.u64;
		}
		ret = SCLIB_REMOTE_CALL(sysid, epoll_ctl, 5, epaux[sysid],
				op, dfd, net_events, net_data);
		break;
	}

	case SYSCALL_SYSID_LOCAL:
		__sync_fetch_and_or(&sclib_file.fds[epfd].ectl_doms, 1U << SYSCALL_SYSID_LOCAL);
		ret = SCLIB_LOCAL_CALL(epoll_ctl, 4, lepfd, op, dfd, event);
		break;

	case SYSCALL_SYSID_ALL: /* For nested epoll */
	{
		long net_events;
		size_t n;
		uint64_t net_data;
		sclib_fd_t *aux = sclib_file_aux(&sclib_file, fd);

		__sync_fetch_and_or(&sclib_file.fds[epfd].ectl_doms, 0xFF);
		if (op == EPOLL_CTL_DEL) {
			net_events = 0;
			net_data = 0;
		} else {
			net_events = event->events;
			net_data = event->data.u64;
		}

		ret = SCLIB_LOCAL_CALL(epoll_ctl, 4, lepfd, op, dfd, event);
		if (!SCLIB_IS_ERR(ret)) {
			for (n = 0; n < SYSCALL_SYSIDS; n++) {
				ret = SCLIB_REMOTE_CALL(n, epoll_ctl, 5, epaux[n],
										op, aux[n], net_events,
										net_data);
				assert(ret == 0); /* Better way to recover? */
			}
		}
		break;
	}
	}

	sclib_file_put(&sclib_file, fd);
error_val:
	sclib_file_put(&sclib_file, epfd);
	SCLIB_ERR_RET(ret);
	return ret;
}
#endif

static inline void __epoll_wait_debug(int epfd, struct epoll_event *events, int maxevents, long ret)
{
	char buf[256];
	char *buf_str;
	int i;

	buf_str = buf;
	buf_str += sprintf(buf_str, "EPOLL_WAIT EFD=%i ", epfd);
	for (i = 0; i < maxevents; i++) {
		buf_str += sprintf(buf_str, "[EVT=0x%x, 0x%llx] ", events[i].events, (unsigned long long) events[i].data.u64);
	}
	buf_str += sprintf(buf_str, "R: %li\n", ret);
	SCLIB_LOCAL_CALL(write, 3, -1, buf, strlen(buf));
}

/*
 * epoll_wait()
 */
#ifdef __NR_epoll_wait

static int __syscall_epoll_wait(int epfd, struct epoll_event *events,
	int maxevents, int timeout)
{
	struct epoll_event *rem_events[SYSCALL_SYSIDS];
	struct syscall_efd param;
	sclib_fd_t *epaux;
	long num, ret, eplfd, efd, efd_packed;
	syscall_entry_t *pos[SYSCALL_SYSIDS];
	size_t sysid;
	uint8_t ectl_doms, mask;

//	__epoll_wait_debug(epfd, events, maxevents, num);

	eplfd = sclib_file_get(&sclib_file, epfd, SYSCALL_SYSID_ALL);
	SCLIB_ERR_RET(eplfd);
	if ((unsigned int) maxevents > 1024)
		maxevents = 1024;
	epaux = sclib_file_aux(&sclib_file, epfd);
	ectl_doms = sclib_file.fds[epfd].ectl_doms;

	mask = 0xFF;
	efd = sclib_thread.efd[SYSCALL_SYSIDS];
	for (sysid = 0; sysid < SYSCALL_SYSIDS; sysid++) {
		rem_events[sysid] = sclib_memory_alloc(&sclib_data[sysid],
								sizeof(struct epoll_event) * maxevents);
		SCLIB_MEM_RET(rem_events[sysid], num);
		if (ectl_doms & (1U << sysid)) {
			mask = ~(1U << sysid);
			if (ectl_doms & mask) {
				efd_packed = sclib_thread.efd[sysid] | (efd << 10);
			} else {
				efd_packed = 0xFFFFF;
			}
			efd_packed |= ((long) epaux[sysid] << 20);
			pos[sysid] = SCLIB_REMOTE_CALL_ASYNC(sysid, syscall_service_epoll_wait, 4, efd_packed, sclib_mem(sysid, rem_events[sysid]), maxevents, timeout);
		}
	}

	num = 0;
	if ((ectl_doms & mask) || ectl_doms == 0) {
		param.efd[SYSCALL_SYSIDS] = efd;
		param.n = eplfd;
		if (ectl_doms & ~(1U << SYSCALL_SYSID_LOCAL)) {
			param.efd_num = -1;
			for (sysid = 0; sysid < SYSCALL_SYSIDS; sysid++) {
				if (ectl_doms & (1U << sysid)) {
					param.efd[sysid] = sclib_thread.efd[sysid];
				} else {
					param.efd[sysid] = -1; /* CHECK!!! */
				}
			}
		} else {
			param.efd_num = 0;
			efd = -1;
		}
		num = SCLIB_LOCAL_CALL(syscall_service_epoll_wait, 4, &param,
			events, maxevents, timeout);
		if (likely(num != -EFAULT))
			sclib_wait_efd(&param, efd);
	}

	SCLIB_VAL_RET(num, num);
	events += num;
	while (sysid != 0) {
		sysid--;
		if (ectl_doms & (1U << sysid)) {
			ret = SCLIB_REMOTE_CALL_RESULT(sysid, syscall_service_epoll_wait, pos[sysid]);
			SCLIB_VAL_RET(ret, num);
			if (num + ret > maxevents)
				ret = maxevents - num;
			events = mempcpy(events, rem_events[sysid], ret * sizeof(struct epoll_event));
			sclib_memory_free(&sclib_data[sysid], rem_events[sysid]);
			num += ret;
		}
	}

error:
	sclib_file_put(&sclib_file, epfd);

//	__epoll_wait_debug(epfd, events, maxevents, num);

	SCLIB_ERR_RET(num);
	return num;

error_mem:
error_val:
	while (sysid != 0) {
		sysid--;
		SCLIB_REMOTE_CALL_RESULT(sysid, syscall_service_epoll_wait, pos[sysid]);
		sclib_memory_free(&sclib_data[sysid], rem_events[sysid]);
	}
	goto error;
}

extern __typeof(epoll_wait) __libc_epoll_wait;
int __libc_epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout)
{
	if (SINGLE_THREAD_P)
		return __syscall_epoll_wait(epfd, events, maxevents, timeout);
# ifdef __UCLIBC_HAS_THREADS_NATIVE__
	else {
		int oldtype = LIBC_CANCEL_ASYNC ();
		int result = __syscall_epoll_wait(epfd, events, maxevents, timeout);
		LIBC_CANCEL_RESET (oldtype);
		return result;
	}
# endif
}
weak_alias(__libc_epoll_wait, epoll_wait)
#endif

/*
 * epoll_pwait()
 */
#ifdef __NR_epoll_wait
# include <signal.h>

static int __syscall_epoll_pwait(int epfd, struct epoll_event *events,
	int maxevents, int timeout, const sigset_t *sigmask)
{
  int retval;
  sigset_t savemask;

  /* The setting and restoring of the signal mask and the epoll_wait call
     should be an atomic operation.  This can't be done without kernel
     help.  */
  if (sigmask != NULL)
    sigprocmask (SIG_SETMASK, sigmask, &savemask);

  /* Note the epoll_pwait() is a cancellation point.  But since we call
     epoll_wait() which itself is a cancellation point we do not have
     to do anything here.  */
  retval = epoll_wait (epfd, events, maxevents, timeout);

  if (sigmask != NULL)
    sigprocmask (SIG_SETMASK, &savemask, NULL);

  return retval;
}


extern __typeof(epoll_pwait) __libc_epoll_pwait;
int __libc_epoll_pwait(int epfd, struct epoll_event *events, int maxevents,
						int timeout, const sigset_t *set)
{
	if (SINGLE_THREAD_P)
		return __syscall_epoll_pwait(epfd, events, maxevents, timeout, set);
# ifdef __UCLIBC_HAS_THREADS_NATIVE__
	else {
		int oldtype = LIBC_CANCEL_ASYNC ();
		int result = __syscall_epoll_pwait(epfd, events, maxevents, timeout, set);
		LIBC_CANCEL_RESET (oldtype);
		return result;
	}
# endif
}
weak_alias(__libc_epoll_pwait, epoll_pwait)
#endif
