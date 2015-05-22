/* Copyright (C) 1994,1996,1997,1998,1999,2001,2002
   Copyright (C) 2012 Ruslan Nikolaev <rnikola@vt.edu>
   Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

#include <sys/syscall.h>
#include <sys/poll.h>
#include <bits/kernel-features.h>

#include <bits/sclib.h>

#ifdef __UCLIBC_HAS_THREADS_NATIVE__
#include <sysdep-cancel.h>
#else
#define SINGLE_THREAD_P 1
#endif

libc_hidden_proto(poll)

#if defined __ASSUME_POLL_SYSCALL && defined __NR_poll

#include <string.h>

static inline void __syscall_poll_debug(struct pollfd *fds, unsigned long nfds, long num)
{
	char buf[256], *buf_ptr;
    unsigned long i;

	if (num != -4096) {
		SCLIB_STRACE_DEBUG("POLL, return %li", num);
	} else {
		SCLIB_STRACE_DEBUG("POLL %lu", nfds);
	}
	buf_ptr = buf;
	for (i = 0; i < nfds; i++) {
		buf_ptr += sprintf(buf_ptr, "{FD=%i", fds[i].fd);
		if (fds[i].events & POLLIN)
			buf_ptr = stpcpy(buf_ptr, " I:IN");
		if (fds[i].events & POLLOUT)
			buf_ptr = stpcpy(buf_ptr, " I:OUT");
		if (fds[i].events & POLLPRI)
			buf_ptr = stpcpy(buf_ptr, " I:PRI");
		if (fds[i].events & POLLRDHUP)
			buf_ptr = stpcpy(buf_ptr, " I:RDHUP");
		if (num == -4096) {
			if (fds[i].revents & POLLIN)
				buf_ptr = stpcpy(buf_ptr, " R:IN");
			if (fds[i].revents & POLLOUT)
				buf_ptr = stpcpy(buf_ptr, " R:OUT");
			if (fds[i].revents & POLLERR)
				buf_ptr = stpcpy(buf_ptr, " R:ERR");
			if (fds[i].revents & POLLPRI)
				buf_ptr = stpcpy(buf_ptr, " R:PRI");
			if (fds[i].revents & POLLRDHUP)
				buf_ptr = stpcpy(buf_ptr, " R:RDHUP");
			if (fds[i].revents & POLLNVAL)
				buf_ptr = stpcpy(buf_ptr, " R:NVAL");
			if (fds[i].revents & POLLHUP)
				buf_ptr = stpcpy(buf_ptr, " R:HUP");
		}
		buf_ptr = stpcpy(buf_ptr, "}");
	}
	SCLIB_LOCAL_CALL(write, 3, -1, buf, strlen(buf));
}

static inline long __syscall_poll(struct pollfd *fds, unsigned long nfds,
	int timeout)
{
	struct pollfd loc_fds[1025];
	struct pollfd *rem_fds[SYSCALL_SYSIDS], *cur_fds;
	struct syscall_efd param;
	unsigned long n, i, rem_num[SYSCALL_SYSIDS], cur_num, loc_num = 0;
	long num, ret, dfd, dom_num;
	int sysid;
	syscall_entry_t *pos[SYSCALL_SYSIDS];

	//__syscall_poll_debug(fds, nfds, -4096);
	if (unlikely((unsigned int) nfds > 1024)) {
		num = -EINVAL;
		goto error;
	}

	memset(rem_fds, 0, sizeof(rem_fds));
	dom_num = 0;
	for (n = 0; n < nfds; n++) {
		dfd = sclib_file_getid(&sclib_file, fds[n].fd, &sysid);
		if (dfd < 0) {
			fds[n].revents = POLLNVAL;
		} else {
			fds[n].revents = 0;
			if (sysid != SYSCALL_SYSID_LOCAL) {
				cur_fds = rem_fds[sysid];
				if (cur_fds == NULL) {
					cur_fds = sclib_memory_alloc(&sclib_data[sysid],
						sizeof(struct pollfd) * (nfds + 1));
					SCLIB_MEM_RET(cur_fds, num);
					rem_fds[sysid] = cur_fds;
					rem_num[sysid] = 0;
					dom_num++;
				}
				cur_num = rem_num[sysid];
				cur_fds[cur_num].fd = dfd;
				cur_fds[cur_num].events = fds[n].events;
				cur_fds[cur_num++].revents = 0; /* Just in case */
				rem_num[sysid] = cur_num;
			} else {
				loc_fds[loc_num].fd = dfd;
				loc_fds[loc_num].events = fds[n].events;
				loc_fds[loc_num++].revents = 0; /* Just in case */
			}
		}
	}
	dom_num += (loc_num != 0);

	for (sysid = 0; sysid < SYSCALL_SYSIDS; sysid++) {
		cur_num = rem_num[sysid];
		cur_fds = rem_fds[sysid];
		if (cur_fds) {
			long efd_packed;
			if (dom_num > 1) {
				efd_packed = sclib_thread.efd[sysid];
				cur_fds[cur_num].fd = efd_packed;
				cur_fds[cur_num].events = POLLIN;
				cur_fds[cur_num++].revents = 0;
				rem_num[sysid] = cur_num;
				efd_packed |= sclib_thread.efd[SYSCALL_SYSIDS] << 10;
			} else {
				efd_packed = 0xFFFFF;
			}
			efd_packed |= (cur_num << 20);
			pos[sysid] = SCLIB_REMOTE_CALL_ASYNC(sysid, syscall_service_poll, 3,
							sclib_mem(sysid, cur_fds), efd_packed, timeout);
		}
	}

	ret = 0;
	if (dom_num != 1 || loc_num != 0) {
		long efd;
		if (dom_num > 1) {
			efd = sclib_thread.efd[SYSCALL_SYSIDS];
			param.efd[SYSCALL_SYSIDS] = efd;
			loc_fds[loc_num].fd = efd;
			loc_fds[loc_num].events = POLLIN;
			loc_fds[loc_num++].revents = 0;
			param.efd_num = -1;
			for (sysid = 0; sysid < SYSCALL_SYSIDS; sysid++)
				param.efd[sysid] = rem_fds[sysid] ? sclib_thread.efd[sysid] : -1;
		} else {
			param.efd_num = 0;
			efd = -1;
		}
		param.n = loc_num;
		ret = SCLIB_LOCAL_CALL(syscall_service_poll, 3, loc_fds, &param,
			timeout);
		if (likely(ret != -EFAULT))
			sclib_wait_efd(&param, efd);
	}

	/* Get result from the remote domain */
	for (sysid = 0; sysid < SYSCALL_SYSIDS; sysid++) {
		if (!rem_fds[sysid])
			continue;
		num = SCLIB_REMOTE_CALL_RESULT(sysid, syscall_service_poll, pos[sysid]);
		if (SCLIB_IS_ERR(num))
			ret = num;
	}

	SCLIB_VAL_RET(ret, num);

	memset(rem_num, 0, sizeof(rem_num));
	loc_num = 0;
	num = 0;
	for (i = 0; i < n; i++) {
		if (fds[i].revents == 0) {
			dfd = sclib_file_touch(&sclib_file, fds[i].fd, &sysid);
			if (sysid != SYSCALL_SYSID_LOCAL) {
				fds[i].revents = rem_fds[sysid][rem_num[sysid]++].revents;
			} else {
				fds[i].revents = loc_fds[loc_num++].revents;
			}
		} else if (fds[i].fd < 0) { /* If (fd < 0), we have to set it to 0. */
			fds[i].revents = 0;
		}
		num += (fds[i].revents != 0);
	}

error_val:
error_mem:
	for (i = 0; i < n; i++)
		sclib_file_put(&sclib_file, fds[i].fd);
	for (sysid = 0; sysid < SYSCALL_SYSIDS; sysid++) {
		cur_fds = rem_fds[sysid];
		if (cur_fds != NULL)
			sclib_memory_free(&sclib_data[sysid], cur_fds);
	}
error:
//__syscall_poll_debug(fds, nfds, num);
	SCLIB_ERR_RET(num);
	return num;
}

int poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    if (SINGLE_THREAD_P)
	return __syscall_poll(fds, nfds, timeout);

#ifdef __UCLIBC_HAS_THREADS_NATIVE__
    int oldtype = LIBC_CANCEL_ASYNC ();
    int result = __syscall_poll(fds, nfds, timeout);
    LIBC_CANCEL_RESET (oldtype);
    return result;
#endif
}
#else /* !__NR_poll */

#include <alloca.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>
#include <sys/time.h>
#include <sys/param.h>
#include <unistd.h>

libc_hidden_proto(getdtablesize)
libc_hidden_proto(select)

/* uClinux 2.0 doesn't have poll, emulate it using select */

/* Poll the file descriptors described by the NFDS structures starting at
   FDS.  If TIMEOUT is nonzero and not -1, allow TIMEOUT milliseconds for
   an event to occur; if TIMEOUT is -1, block until an event occurs.
   Returns the number of file descriptors with events, zero if timed out,
   or -1 for errors.  */

int poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    static int max_fd_size;
    struct timeval tv;
    fd_set *rset, *wset, *xset;
    struct pollfd *f;
    int ready;
    int maxfd = 0;
    int bytes;

    if (!max_fd_size)
	max_fd_size = getdtablesize ();

    bytes = howmany (max_fd_size, __NFDBITS);
    rset = alloca (bytes);
    wset = alloca (bytes);
    xset = alloca (bytes);

    /* We can't call FD_ZERO, since FD_ZERO only works with sets
       of exactly __FD_SETSIZE size.  */
    memset (rset, 0, bytes);
    memset (wset, 0, bytes);
    memset (xset, 0, bytes);

    for (f = fds; f < &fds[nfds]; ++f)
    {
	f->revents = 0;
	if (f->fd >= 0)
	{
	    if (f->fd >= max_fd_size)
	    {
		/* The user provides a file descriptor number which is higher
		   than the maximum we got from the `getdtablesize' call.
		   Maybe this is ok so enlarge the arrays.  */
		fd_set *nrset, *nwset, *nxset;
		int nbytes;

		max_fd_size = roundup (f->fd, __NFDBITS);
		nbytes = howmany (max_fd_size, __NFDBITS);

		nrset = alloca (nbytes);
		nwset = alloca (nbytes);
		nxset = alloca (nbytes);

		memset ((char *) nrset + bytes, 0, nbytes - bytes);
		memset ((char *) nwset + bytes, 0, nbytes - bytes);
		memset ((char *) nxset + bytes, 0, nbytes - bytes);

		rset = memcpy (nrset, rset, bytes);
		wset = memcpy (nwset, wset, bytes);
		xset = memcpy (nxset, xset, bytes);

		bytes = nbytes;
	    }

	    if (f->events & POLLIN)
		FD_SET (f->fd, rset);
	    if (f->events & POLLOUT)
		FD_SET (f->fd, wset);
	    if (f->events & POLLPRI)
		FD_SET (f->fd, xset);
	    if (f->fd > maxfd && (f->events & (POLLIN|POLLOUT|POLLPRI)))
		maxfd = f->fd;
	}
    }

    tv.tv_sec = timeout / 1000;
    tv.tv_usec = (timeout % 1000) * 1000;

    while (1)
    {
	ready = select (maxfd + 1, rset, wset, xset,
		timeout == -1 ? NULL : &tv);

	/* It might be that one or more of the file descriptors is invalid.
	   We now try to find and mark them and then try again.  */
	if (ready == -1 && errno == EBADF)
	{
	    fd_set *sngl_rset = alloca (bytes);
	    fd_set *sngl_wset = alloca (bytes);
	    fd_set *sngl_xset = alloca (bytes);
	    struct timeval sngl_tv;

	    /* Clear the original set.  */
	    memset (rset, 0, bytes);
	    memset (wset, 0, bytes);
	    memset (xset, 0, bytes);

	    /* This means we don't wait for input.  */
	    sngl_tv.tv_sec = 0;
	    sngl_tv.tv_usec = 0;

	    maxfd = -1;

	    /* Reset the return value.  */
	    ready = 0;

	    for (f = fds; f < &fds[nfds]; ++f)
		if (f->fd != -1 && (f->events & (POLLIN|POLLOUT|POLLPRI))
			&& (f->revents & POLLNVAL) == 0)
		{
		    int n;

		    memset (sngl_rset, 0, bytes);
		    memset (sngl_wset, 0, bytes);
		    memset (sngl_xset, 0, bytes);

		    if (f->events & POLLIN)
			FD_SET (f->fd, sngl_rset);
		    if (f->events & POLLOUT)
			FD_SET (f->fd, sngl_wset);
		    if (f->events & POLLPRI)
			FD_SET (f->fd, sngl_xset);

		    n = select (f->fd + 1, sngl_rset, sngl_wset, sngl_xset,
			    &sngl_tv);
		    if (n != -1)
		    {
			/* This descriptor is ok.  */
			if (f->events & POLLIN)
			    FD_SET (f->fd, rset);
			if (f->events & POLLOUT)
			    FD_SET (f->fd, wset);
			if (f->events & POLLPRI)
			    FD_SET (f->fd, xset);
			if (f->fd > maxfd)
			    maxfd = f->fd;
			if (n > 0)
			    /* Count it as being available.  */
			    ++ready;
		    }
		    else if (errno == EBADF)
			f->revents |= POLLNVAL;
		}
	    /* Try again.  */
	    continue;
	}

	break;
    }

    if (ready > 0)
	for (f = fds; f < &fds[nfds]; ++f)
	{
	    if (f->fd >= 0)
	    {
		if (FD_ISSET (f->fd, rset))
		    f->revents |= POLLIN;
		if (FD_ISSET (f->fd, wset))
		    f->revents |= POLLOUT;
		if (FD_ISSET (f->fd, xset))
		    f->revents |= POLLPRI;
	    }
	}

    return ready;
}

#endif
libc_hidden_def(poll)
