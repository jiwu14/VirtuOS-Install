/* Copyright (C) 2006   Manuel Novoa III    <mjn3@codepoet.org>
 *
 * GNU Library General Public License (LGPL) version 2 or later.
 *
 * Dedicated to Toni.  See uClibc/DEDICATION.mjn3 for details.
 */

#ifndef _UCLIBC_MUTEX_H
#define _UCLIBC_MUTEX_H

#include <features.h>

#ifdef __UCLIBC_HAS_THREADS__

#include <pthread.h>
#include <bits/uClibc_pthread.h>
#include <schedule_defsP.h>
#include <bits/stdio-lock.h>

#define __UCLIBC_MUTEX_TYPE				struct __sclib_mutex_auto

#define __UCLIBC_MUTEX(M)				struct __sclib_mutex_auto M
#define __UCLIBC_MUTEX_INIT(M,I)			struct __sclib_mutex_auto M = { .kind = I, .value = 0, .owner = 0, .recur_count = 0 }
#define __UCLIBC_MUTEX_STATIC(M,I)			static struct __sclib_mutex_auto M = { .kind = I, .value = 0, .owner = 0, .recur_count = 0 }
#define __UCLIBC_MUTEX_EXTERN(M)			extern struct __sclib_mutex_auto M

#define __UCLIBC_MUTEX_INIT_VAR(M)								\
		__sclib_mutex_auto_init(&(M), __SCLIB_MUTEX_RECURSIVE)

#define __UCLIBC_MUTEX_LOCK_CANCEL_UNSAFE(M)								\
		__sclib_mutex_auto_lock(&(M))

#define __UCLIBC_MUTEX_UNLOCK_CANCEL_UNSAFE(M)								\
		__sclib_mutex_auto_unlock(&(M))

#define __UCLIBC_MUTEX_TRYLOCK_CANCEL_UNSAFE(M)								\
		__sclib_mutex_auto_trylock(&(M))

#define __UCLIBC_MUTEX_CONDITIONAL_LOCK(M,C)								\
	do {												\
		struct _pthread_cleanup_buffer __infunc_pthread_cleanup_buffer;				\
		int __infunc_need_locking = (C);							\
		if (__infunc_need_locking) {								\
			_pthread_cleanup_push_defer(&__infunc_pthread_cleanup_buffer,			\
					   (void (*) (void *))__sclib_mutex_auto_unlock,		\
										&(M));			\
			__sclib_mutex_auto_lock(&(M));							\
		}											\
		((void)0)

#define __UCLIBC_MUTEX_CONDITIONAL_UNLOCK(M,C)								\
		if (__infunc_need_locking) {								\
			_pthread_cleanup_pop_restore(&__infunc_pthread_cleanup_buffer,1);		\
		}											\
	} while (0)

#define __UCLIBC_MUTEX_AUTO_LOCK_VAR(A)		int A

#define __UCLIBC_MUTEX_AUTO_LOCK(M,A,V)									\
        __UCLIBC_MUTEX_CONDITIONAL_LOCK(M,((A=(V)) == 0))

#define __UCLIBC_MUTEX_AUTO_UNLOCK(M,A)									\
        __UCLIBC_MUTEX_CONDITIONAL_UNLOCK(M,(A == 0))

#define __UCLIBC_MUTEX_LOCK(M)										\
        __UCLIBC_MUTEX_CONDITIONAL_LOCK(M, 1)

#define __UCLIBC_MUTEX_UNLOCK(M)									\
        __UCLIBC_MUTEX_CONDITIONAL_UNLOCK(M, 1)

#if 0

#include <bits/stdio-lock.h>

#define __UCLIBC_IO_MUTEX(M)			_IO_lock_t M
#define __UCLIBC_IO_MUTEX_LOCK(M) 		_IO_lock_lock(M)
#define __UCLIBC_IO_MUTEX_UNLOCK(M) 	_IO_lock_unlock(M)
#define __UCLIBC_IO_MUTEX_TRYLOCK(M) 	_IO_lock_trylock(M)
#define __UCLIBC_IO_MUTEX_INIT(M) 	_IO_lock_t M = _IO_lock_initializer
#define __UCLIBC_IO_MUTEX_EXTERN(M)		extern _IO_lock_t M

#define __UCLIBC_IO_MUTEX_CONDITIONAL_LOCK(M,C)		\
	if (C) {										\
		_IO_lock_lock(M);							\
	}

#define __UCLIBC_IO_MUTEX_CONDITIONAL_UNLOCK(M,C)	\
	if (C) {										\
		_IO_lock_unlock(M);							\
	}

#define __UCLIBC_IO_MUTEX_AUTO_LOCK(M,A,V)			\
		__UCLIBC_IO_MUTEX_CONDITIONAL_LOCK(M,((A=(V))) == 0)

#define __UCLIBC_IO_MUTEX_AUTO_UNLOCK(M,A)			\
		__UCLIBC_IO_MUTEX_CONDITIONAL_UNLOCK(M,((A) == 0))

#define __UCLIBC_IO_MUTEX_LOCK_CANCEL_UNSAFE(M)		_IO_lock_lock(M)
#define __UCLIBC_IO_MUTEX_UNLOCK_CANCEL_UNSAFE(M) 	_IO_lock_unlock(M)

#else /* of __USE_STDIO_FUTEXES__ */

#define __UCLIBC_IO_MUTEX(M)                        __UCLIBC_MUTEX(M)
#define __UCLIBC_IO_MUTEX_LOCK(M)                   __UCLIBC_MUTEX_CONDITIONAL_LOCK(M, 1)
#define __UCLIBC_IO_MUTEX_UNLOCK(M)                 __UCLIBC_MUTEX_CONDITIONAL_UNLOCK(M, 1)
#define __UCLIBC_IO_MUTEX_TRYLOCK(M)                __UCLIBC_MUTEX_TRYLOCK_CANCEL_UNSAFE(M)
#define __UCLIBC_IO_MUTEX_INIT(M)                   __UCLIBC_MUTEX_INIT(M, __SCLIB_MUTEX_RECURSIVE)
#define __UCLIBC_IO_MUTEX_EXTERN(M)                 __UCLIBC_MUTEX_EXTERN(M)
#define __UCLIBC_IO_MUTEX_AUTO_LOCK(M,A,V)          __UCLIBC_MUTEX_AUTO_LOCK(M,A,V)
#define __UCLIBC_IO_MUTEX_AUTO_UNLOCK(M,A)          __UCLIBC_MUTEX_AUTO_UNLOCK(M,A)
#define __UCLIBC_IO_MUTEX_LOCK_CANCEL_UNSAFE(M)     __UCLIBC_MUTEX_LOCK_CANCEL_UNSAFE(M)
#define __UCLIBC_IO_MUTEX_UNLOCK_CANCEL_UNSAFE(M)   __UCLIBC_MUTEX_UNLOCK_CANCEL_UNSAFE(M)
#define __UCLIBC_IO_MUTEX_CONDITIONAL_LOCK(M,C)     __UCLIBC_MUTEX_CONDITIONAL_LOCK(M, 1)
#define __UCLIBC_IO_MUTEX_CONDITIONAL_UNLOCK(M,C)   __UCLIBC_MUTEX_CONDITIONAL_UNLOCK(M, 1)

#endif /* of __USE_STDIO_FUTEXES__ */


#else /* of __UCLIBC_HAS_THREADS__ */

#define __UCLIBC_MUTEX(M)				void *__UCLIBC_MUTEX_DUMMY_ ## M
#define __UCLIBC_MUTEX_INIT(M,I)			extern void *__UCLIBC_MUTEX_DUMMY_ ## M
#define __UCLIBC_MUTEX_STATIC(M,I)			extern void *__UCLIBC_MUTEX_DUMMY_ ## M
#define __UCLIBC_MUTEX_EXTERN(M)			extern void *__UCLIBC_MUTEX_DUMMY_ ## M

#define __UCLIBC_MUTEX_INIT_VAR(M)					((void)0)
#define __UCLIBC_MUTEX_LOCK_CANCEL_UNSAFE(M)		((void)0)
#define __UCLIBC_MUTEX_UNLOCK_CANCEL_UNSAFE(M)		((void)0)
#define __UCLIBC_MUTEX_TRYLOCK_CANCEL_UNSAFE(M)		(0)	/* Always succeed? */

#define __UCLIBC_MUTEX_CONDITIONAL_LOCK(M,C)		((void)0)
#define __UCLIBC_MUTEX_CONDITIONAL_UNLOCK(M,C)		((void)0)

#define __UCLIBC_MUTEX_AUTO_LOCK_VAR(A)			((void)0)
#define __UCLIBC_MUTEX_AUTO_LOCK(M,A,V)			((void)0)
#define __UCLIBC_MUTEX_AUTO_UNLOCK(M,A)			((void)0)

#define __UCLIBC_MUTEX_LOCK(M)				((void)0)
#define __UCLIBC_MUTEX_UNLOCK(M)			((void)0)

#define __UCLIBC_IO_MUTEX(M)                        __UCLIBC_MUTEX(M)
#define __UCLIBC_IO_MUTEX_LOCK(M)                   __UCLIBC_MUTEX_CONDITIONAL_LOCK(M, 1)
#define __UCLIBC_IO_MUTEX_UNLOCK(M)                 __UCLIBC_MUTEX_CONDITIONAL_UNLOCK(M, 1)
#define __UCLIBC_IO_MUTEX_TRYLOCK(M)                __UCLIBC_MUTEX_TRYLOCK_CANCEL_UNSAFE(M)
#define __UCLIBC_IO_MUTEX_INIT(M)                   __UCLIBC_MUTEX_INIT(M, __SCLIB_MUTEX_RECURSIVE)
#define __UCLIBC_IO_MUTEX_EXTERN(M)                 __UCLIBC_MUTEX_EXTERN(M)
#define __UCLIBC_IO_MUTEX_AUTO_LOCK(M,A,V)          __UCLIBC_MUTEX_AUTO_LOCK(M,A,V)
#define __UCLIBC_IO_MUTEX_AUTO_UNLOCK(M,A)          __UCLIBC_MUTEX_AUTO_UNLOCK(M,A)
#define __UCLIBC_IO_MUTEX_LOCK_CANCEL_UNSAFE(M)     __UCLIBC_MUTEX_LOCK_CANCEL_UNSAFE(M)
#define __UCLIBC_IO_MUTEX_UNLOCK_CANCEL_UNSAFE(M)   __UCLIBC_MUTEX_UNLOCK_CANCEL_UNSAFE(M)
#define __UCLIBC_IO_MUTEX_CONDITIONAL_LOCK(M,C)     __UCLIBC_MUTEX_CONDITIONAL_LOCK(M, 1)
#define __UCLIBC_IO_MUTEX_CONDITIONAL_UNLOCK(M,C)   __UCLIBC_MUTEX_CONDITIONAL_UNLOCK(M, 1)

#endif /* of __UCLIBC_HAS_THREADS__ */

#define __UCLIBC_IO_MUTEX_TRYLOCK_CANCEL_UNSAFE(M)	\
		__UCLIBC_IO_MUTEX_TRYLOCK(M)

#endif /* _UCLIBC_MUTEX_H */
