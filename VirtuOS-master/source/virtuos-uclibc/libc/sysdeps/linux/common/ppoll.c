/* Copyright (C) 2006 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@redhat.com>, 2006.

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

#include <signal.h>
#include <sys/syscall.h>
#include <sys/poll.h>
#define __need_NULL
#include <stddef.h>

#if defined __ASSUME_POLL_SYSCALL && defined __NR_poll
# ifdef __UCLIBC_HAS_THREADS_NATIVE__
#  include <sysdep-cancel.h>
# else
#  define SINGLE_THREAD_P 1
# endif

#ifdef __UCLIBC_HAS_THREADS_NATIVE__
static int __ppoll
#else
int ppoll
#endif
	(struct pollfd *fds, nfds_t nfds, const struct timespec *timeout,
       const sigset_t *sigmask)
{
  struct timeval tval;
  int retval;
  sigset_t savemask;

  /* Change nanosecond number to microseconds.  This might mean losing
     precision and therefore the `ppoll` should be available.  But
     for now it is hardly found.  */
  if (timeout != NULL)
    TIMESPEC_TO_TIMEVAL (&tval, timeout);

  /* The setting and restoring of the signal mask and the poll call
     should be an atomic operation.  This can't be done without kernel
     help.  */
  if (sigmask != NULL)
    sigprocmask (SIG_SETMASK, sigmask, &savemask);

  /* Note the ppoll() is a cancellation point.  But since we call
     poll() which itself is a cancellation point we do not have
     to do anything here.  */
  retval = poll (fds, nfds, timeout != NULL ? &tval : NULL);

  if (sigmask != NULL)
    sigprocmask (SIG_SETMASK, &savemask, NULL);

  return retval;
}

#ifdef __UCLIBC_HAS_THREADS_NATIVE__
int
ppoll (struct pollfd *fds, nfds_t nfds, const struct timespec *timeout,
		const sigset_t *sigmask)
{
	if (SINGLE_THREAD_P)
		return __ppoll (fds, nfds, timeout, sigmask);

	int oldtype = LIBC_CANCEL_ASYNC ();

	int result = __ppoll (fds, nfds, timeout, sigmask);

	LIBC_CANCEL_RESET (oldtype);

	return result;
}
#endif

libc_hidden_def(ppoll)
#endif
