/*  Copyright (C) 2003     Manuel Novoa III
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  The GNU C Library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with the GNU C Library; if not, write to the Free
 *  Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
 *  02111-1307 USA.
 */

/* Supply prototypes for the internal thread functions used by the
 * uClibc library code.
 */

#ifndef _UCLIBC_PTHREAD_H
#define _UCLIBC_PTHREAD_H

#ifndef _PTHREAD_H
# error "Always include <pthread.h> rather than <bits/uClibc_pthread.h>"
#endif

#if defined _LIBC && (defined IS_IN_libc || defined NOT_IN_libc)

struct _pthread_cleanup_buffer;

/* Threading functions internal to uClibc.  Make these thread functions
 * weak so that we can elide them from single-threaded processes.  */
extern int weak_function __pthread_mutex_init (pthread_mutex_t *__mutex,
		__const pthread_mutexattr_t *__mutex_attr);
extern int weak_function __pthread_mutex_reinit (pthread_mutex_t *__mutex);
extern int weak_function __pthread_mutex_destroy (pthread_mutex_t *__mutex);
extern int weak_function __pthread_mutex_lock (pthread_mutex_t *__mutex);
extern int weak_function __pthread_mutex_unlock (pthread_mutex_t *__mutex);
extern int weak_function __pthread_mutex_trylock (pthread_mutex_t *__mutex);
extern void weak_function _pthread_cleanup_push_defer (
		struct _pthread_cleanup_buffer *__buffer,
		void (*__routine) (void *), void *__arg);
extern void weak_function _pthread_cleanup_pop_restore (
		struct _pthread_cleanup_buffer *__buffer,
		int __execute);

struct __sclib_mutex;
struct __sclib_mutex_auto;
struct syscall_entry;

extern long weak_function __sclib_futex_wait(int *ptr, int val);
extern long weak_function __sclib_futex_wake(int *ptr, int val);
extern void weak_function __sclib_schedule(int sysid, struct syscall_entry *entry);
extern long weak_function __sclib_mutex_auto_init(struct __sclib_mutex_auto *mutex, int kind);
extern long weak_function __sclib_mutex_auto_reinit(struct __sclib_mutex_auto *mutex);
extern void weak_function __sclib_mutex_auto_destroy(struct __sclib_mutex_auto *mutex);
extern long weak_function __sclib_mutex_auto_lock(struct __sclib_mutex_auto *mutex);
extern long weak_function __sclib_mutex_auto_trylock(struct __sclib_mutex_auto *mutex);
extern long weak_function __sclib_mutex_auto_unlock(struct __sclib_mutex_auto *mutex);

#endif

#endif
