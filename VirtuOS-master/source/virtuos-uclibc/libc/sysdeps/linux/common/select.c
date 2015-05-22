/* vi: set sw=4 ts=4: */
/*
 * select() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 * Copyright (C) 2012 Ruslan Nikolaev <rnikola@vt.edu>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <sys/select.h>
#include <stdint.h>

#include <string.h>
#include <bits/sclib.h>

#ifdef __UCLIBC_HAS_THREADS_NATIVE__
#include <sysdep-cancel.h>
#else
#define SINGLE_THREAD_P 1
#endif

#define USEC_PER_SEC 1000000L

extern __typeof(select) __libc_select;

#if !defined(__NR__newselect) && !defined(__NR_select) && defined __USE_XOPEN2K
# define __NR___libc_pselect6 __NR_pselect6
static _syscall6(int, __libc_pselect6, int, n, fd_set *, readfds, fd_set *, writefds,
        fd_set *, exceptfds, const struct timespec *, timeout,
        const sigset_t *, sigmask)

int __libc_select(int n, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
                  struct timeval *timeout)
{
	struct timespec _ts, *ts = 0;
	if (timeout) {
		uint32_t usec;
		_ts.tv_sec = timeout->tv_sec;

		/* GNU extension: allow for timespec values where the sub-sec
		* field is equal to or more than 1 second.  The kernel will
		* reject this on us, so take care of the time shift ourself.
		* Some applications (like readline and linphone) do this.
		* See 'clarification on select() type calls and invalid timeouts'
		* on the POSIX general list for more information.
		*/
		usec = timeout->tv_usec;
		if (usec >= USEC_PER_SEC) {
			_ts.tv_sec += usec / USEC_PER_SEC;
			usec %= USEC_PER_SEC;
		}
		_ts.tv_nsec = usec * 1000;

		ts = &_ts;
	}

	if (SINGLE_THREAD_P)
		return __libc_pselect6(n, readfds, writefds, exceptfds, ts, 0);
#ifdef __UCLIBC_HAS_THREADS_NATIVE__
	int oldtype = LIBC_CANCEL_ASYNC ();
	int result = __libc_pselect6(n, readfds, writefds, exceptfds, ts, 0);
	LIBC_CANCEL_RESET (oldtype);
	return result;
#endif

}

#else

static long select_convert_input(long *nall, fd_set *fds,
	fd_set *dom[SYSCALL_SYSIDS+1], long domidx, long *ndom)
{
	long n = *nall;
	long fd, dfd, mask = 0;
	int sysid;
	fd_set *cur;

	*nall = 0;
	if (fds != NULL) {
		for (fd = 0; fd < n; fd++) {
			if (FD_ISSET(fd, fds)) {
				dfd = sclib_file_getid(&sclib_file, fd, &sysid);
				if (SCLIB_IS_ERR(dfd))
					return dfd;
				*nall = fd + 1;
				if (!dom[sysid]) {
					dom[sysid] = sclib_memory_alloc(&sclib_data[sysid], 3 * sizeof(fd_set) + sizeof(struct timeval));
					if (dom[sysid] == NULL)
						return -ENOMEM;
				}
				cur = dom[sysid] + domidx;
				if (!(mask & (1U << sysid))) {
					mask |= (1U << sysid);
					FD_ZERO(cur);
				}
				FD_SET(dfd, cur);
				if (dfd >= ndom[sysid])
					ndom[sysid] = dfd + 1;
			}
		}
	}
	return mask;
}

static void select_convert_output(long n, fd_set *fds, fd_set *dom[SYSCALL_SYSIDS+1], long domidx)
{
	long fd, dfd;
	int sysid;
	fd_set *cur;

	if (fds != NULL) {
		for (fd = 0; fd < n; fd++) {
			if (FD_ISSET(fd, fds)) {
				dfd = sclib_file_touch(&sclib_file, fd, &sysid);
				sclib_file_put(&sclib_file, fd);
				cur = dom[sysid] + domidx;
				if (!FD_ISSET(dfd, cur))
					FD_CLR(fd, fds);
			}
		}
	}
}

static inline void __syscall_select_debug(long n, fd_set *rfds, fd_set *wfds, fd_set *efds, struct timeval *timeout)
{
    char buf[256], *buf_ptr;
	long i;

	buf_ptr = stpcpy(buf, "R:[");
	if (rfds != NULL) {
		for (i = 0; i < n; i++) {
			if (FD_ISSET(i, rfds))
				buf_ptr += sprintf(buf_ptr, (i == n - 1) ? "%li" : "%li,", i);
		}
	}
	buf_ptr = stpcpy(buf_ptr, "] W:[");
	if (wfds != NULL) {
		for (i = 0; i < n; i++) {
			if (FD_ISSET(i, wfds))
				buf_ptr += sprintf(buf_ptr, (i == n - 1) ? "%li" : "%li,", i);
		}
	}
	buf_ptr = stpcpy(buf_ptr, "] E:[");
	if (efds != NULL) {
		for (i = 0; i < n; i++) {
			if (FD_ISSET(i, efds))
				buf_ptr += sprintf(buf_ptr, (i == n - 1) ? "%li" : "%li,", i);
		}
	}
	buf_ptr = stpcpy(buf_ptr, "]");
	SCLIB_LOCAL_CALL(write, 3, -1, buf, strlen(buf));
	if (timeout != NULL) {
		SCLIB_STRACE_DEBUG("T:{%li,%li}", timeout->tv_sec, timeout->tv_usec);
	}
}

static long __syscall_select(long n, fd_set *rfds, fd_set *wfds, fd_set *efds,
	struct timeval *timeout)
{
	struct syscall_efd param;
	fd_set loc[3];
	fd_set *dom[SYSCALL_SYSIDS+1], *cur;
	long mask, mask_check, mask_rfds, mask_wfds, mask_efds;
	long rfds_n, wfds_n, efds_n;
	long err, ret, num, ndom[SYSCALL_SYSIDS+1];
	syscall_entry_t *pos[SYSCALL_SYSIDS];
	int timeout_copied, sysid;

	//SCLIB_STRACE_DEBUG("SELECT %li\n", n);
	//__syscall_select_debug(n, rfds, wfds, efds, timeout);

	if (unlikely((unsigned long) n > 1024)) {
		num = -EINVAL;
		goto error4;
	}
	memset(dom, 0, sizeof(dom));
	memset(ndom, 0, sizeof(ndom));

	dom[SYSCALL_SYSID_LOCAL] = loc;
	rfds_n = n;
	num = select_convert_input(&rfds_n, rfds, dom, 0, ndom);

	if (SCLIB_IS_ERR(num))
		goto error3;
	mask = num;
	wfds_n = n;
	num = select_convert_input(&wfds_n, wfds, dom, 1, ndom);

	if (SCLIB_IS_ERR(num))
		goto error2;

	mask |= (num << (SYSCALL_SYSIDS + 1));
	efds_n = n;
	num = select_convert_input(&efds_n, efds, dom, 2, ndom);
	if (SCLIB_IS_ERR(num))
		goto error1;
	mask |= (num << 2 * (SYSCALL_SYSIDS + 1));

	mask_check = ~0L;
	for (sysid = 0; sysid < SYSCALL_SYSIDS; sysid++) {
		cur = dom[sysid];
		mask_rfds = 1UL << sysid;
		mask_wfds = mask_rfds << (SYSCALL_SYSIDS+1);
		mask_efds = mask_wfds << (SYSCALL_SYSIDS+1);
		num = mask_rfds + mask_wfds + mask_efds;
		if (mask & num) { /* ..1..1..1 */
			void *rarg = NULL, *warg = NULL, *earg = NULL, *targ = NULL;
			void *rcur = sclib_mem(sysid, cur);
			long efd_packed;

			mask_check = ~num;
			if (mask & mask_check) {
				if (!(mask & mask_rfds)) { /* No one initialized rfds set yet */
					mask |= mask_rfds;
					FD_ZERO(&cur[0]);
				}
				efd_packed = sclib_thread.efd[sysid];
				FD_SET(efd_packed, &cur[0]);
				if (efd_packed >= ndom[sysid])
					ndom[sysid] = efd_packed + 1;
				efd_packed |= sclib_thread.efd[SYSCALL_SYSIDS] << 10;
			} else {
				efd_packed = 0xFFFFF;
			}
			efd_packed |= (ndom[sysid] << 20);
			if (mask & mask_rfds)
				rarg = rcur;
			if (mask & mask_wfds)
				warg = rcur + sizeof(fd_set);
			if (mask & mask_efds)
				earg = rcur + 2 * sizeof(fd_set);
			if (timeout != NULL) {
				targ = rcur + 3 * sizeof(fd_set);
				memcpy((char *) cur + 3 * sizeof(fd_set), timeout, sizeof(struct timeval)); 
			}
			pos[sysid] = SCLIB_REMOTE_CALL_ASYNC(sysid, syscall_service_select, 5, efd_packed, rarg, warg, earg, targ);
		}
	}

	timeout_copied = (timeout == NULL);
    num = 0;
	if ((mask & mask_check) || mask == 0) {
		long efd;

		mask_rfds = 1UL << SYSCALL_SYSID_LOCAL;
		mask_wfds = mask_rfds << (SYSCALL_SYSIDS+1);
		mask_efds = mask_wfds << (SYSCALL_SYSIDS+1);
		if (mask & ~(mask_rfds + mask_wfds + mask_efds)) {
			param.efd_num = -1;
			efd = sclib_thread.efd[SYSCALL_SYSIDS];
			param.efd[SYSCALL_SYSIDS] = efd;
			if (!(mask & mask_rfds)) { /* No one initialized rfds set yet */
				mask |= mask_rfds;
				FD_ZERO(&loc[0]);
			}
			FD_SET(efd, &loc[0]);
			if (efd >= ndom[SYSCALL_SYSID_LOCAL])
				ndom[SYSCALL_SYSID_LOCAL] = efd + 1;
			for (sysid = 0; sysid < SYSCALL_SYSIDS; sysid++)
				param.efd[sysid] = sclib_thread.efd[sysid];
		} else {
			param.efd_num = 0;
			efd = -1;
		}
		param.n = ndom[SYSCALL_SYSID_LOCAL];
		num = SCLIB_LOCAL_CALL(syscall_service_select, 5, &param,
			(mask & mask_rfds) ? &loc[0] : NULL,
			(mask & mask_wfds) ? &loc[1] : NULL,
			(mask & mask_efds) ? &loc[2] : NULL, timeout);
		timeout_copied = 1;
		if (likely(num != -EFAULT))
			sclib_wait_efd(&param, efd);
	}

	/* Get result from the remote domain */
	err = num;
	if (mask_check != ~0L) {
		for (sysid = 0; sysid < SYSCALL_SYSIDS; sysid++) {
			if (!dom[sysid])
				continue;
			ret = SCLIB_REMOTE_CALL_RESULT(sysid, syscall_service_select, pos[sysid]);
			if (!timeout_copied) {
				memcpy(timeout, (char *) dom[sysid] + 3 * sizeof(fd_set), sizeof(struct timeval));
				timeout_copied = 1;
			}
			if (SCLIB_IS_ERR(ret)) {
				err = ret;
			} else {
				num += ret;
			}
		}
		SCLIB_VAL_RET(err, num);

		/* Correct num value */
		if (mask & (1U << SYSCALL_SYSID_LOCAL)) {
			for (sysid = 0; sysid < SYSCALL_SYSIDS+1; sysid++) {
				if (!dom[sysid])
					continue;
				if (FD_ISSET(sclib_thread.efd[sysid], &dom[sysid][0]))
					num--;
			}
		}
	} else {
		SCLIB_VAL_RET(err, num);
	}

error_val:
error1:
	select_convert_output(efds_n, efds, dom, 2);
error2:
	select_convert_output(wfds_n, wfds, dom, 1);
error3:
	select_convert_output(rfds_n, rfds, dom, 0);

	for (sysid = 0; sysid < SYSCALL_SYSIDS; sysid++) {
		if (!dom[sysid])
			continue;
		sclib_memory_free(&sclib_data[sysid], dom[sysid]);
	}

error4:
	//SCLIB_STRACE_DEBUG("SELECT, result %li\n", num);
	//__syscall_select_debug(n, rfds, wfds, efds, timeout);

	SCLIB_ERR_RET(num);
	return num;
}

int __libc_select(int n, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
                  struct timeval *timeout)
{
	if (SINGLE_THREAD_P)
		return __syscall_select(n, readfds, writefds, exceptfds, timeout);

#ifdef __UCLIBC_HAS_THREADS_NATIVE__
	int oldtype = LIBC_CANCEL_ASYNC ();
	int result = __syscall_select(n, readfds, writefds, exceptfds, timeout);
	LIBC_CANCEL_RESET (oldtype);
	return result;
#endif
}

#endif

weak_alias(__libc_select,select)
libc_hidden_weak(select)
