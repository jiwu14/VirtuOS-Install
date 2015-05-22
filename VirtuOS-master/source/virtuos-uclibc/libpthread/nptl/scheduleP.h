/**
 * VM-Syscalls
 * Copyright (c) 2013 Ruslan Nikolaev <rnikola@vt.edu>
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

#ifndef __SCLIB_SCHEDULEP_H
#define __SCLIB_SCHEDULEP_H

#include <sys/types.h>
#include <stdbool.h>
#include <ucontext.h>
#include <libc-symbols.h>
#include "schedule_defsP.h"

#define __SCLIB_PTHREAD_RUNNING		0
#define __SCLIB_PTHREAD_COMPLETE	1
#define __SCLIB_PTHREAD_BLOCKED		2	/* Must be last */

struct pthread;
struct kpthread;
struct syscall_entry;
struct syscall_queue;

extern size_t __sclib_num_kthreads attribute_hidden;
extern struct syscall_queue *__nptl_rqueue
#ifdef SHARED
attribute_hidden
#else
__attribute ((weak))
#endif
;

extern void __sclib_schedule_init(struct syscall_queue *rqueue) attribute_hidden;
extern void __sclib_initial_switch(struct pthread *from, struct pthread *to) attribute_hidden;
extern void __sclib_initial_add(struct pthread *thread) attribute_hidden;
extern void __sclib_yield(void) attribute_hidden;
extern long __sclib_mutex_init(struct __sclib_mutex *mutex, int kind) attribute_hidden;
extern long __sclib_mutex_reinit(struct __sclib_mutex *mutex) attribute_hidden;
extern void __sclib_mutex_destroy(struct __sclib_mutex *mutex) attribute_hidden;
extern long __sclib_mutex_lock(struct __sclib_mutex *mutex) attribute_hidden;
extern long __sclib_mutex_trylock(struct __sclib_mutex *mutex) attribute_hidden;
extern long __sclib_mutex_unlock(struct __sclib_mutex *mutex) attribute_hidden;
extern long __sclib_cond_init(struct __sclib_cond *cond) attribute_hidden;
extern long __sclib_cond_wait(struct __sclib_cond *cond, struct __sclib_mutex *mutex) attribute_hidden;
extern long __sclib_cond_signal(struct __sclib_cond *cond) attribute_hidden;
extern long __sclib_cond_broadcast(struct __sclib_cond *cond) attribute_hidden;
extern void __sclib_cond_destroy(struct __sclib_cond *cond) attribute_hidden;
extern long __sclib_sem_init(struct __sclib_sem *sem, unsigned int val) attribute_hidden;
extern void __sclib_sem_destroy(struct __sclib_sem *sem) attribute_hidden;
extern long __sclib_sem_wait(struct __sclib_sem *sem) attribute_hidden;
extern long __sclib_sem_trywait(struct __sclib_sem *sem) attribute_hidden;
extern long __sclib_sem_post(struct __sclib_sem *sem) attribute_hidden;
extern long __sclib_rwlock_init(struct __sclib_rwlock *rwlock) attribute_hidden;
extern void __sclib_rwlock_destroy(struct __sclib_rwlock *rwlock) attribute_hidden;
extern long __sclib_rwlock_rdlock(struct __sclib_rwlock *rwlock) attribute_hidden;
extern long __sclib_rwlock_tryrdlock(struct __sclib_rwlock *rwlock) attribute_hidden;
extern long __sclib_rwlock_wrlock(struct __sclib_rwlock *rwlock) attribute_hidden;
extern long __sclib_rwlock_trywrlock(struct __sclib_rwlock *rwlock) attribute_hidden;
extern void __sclib_rwlock_unlock(struct __sclib_rwlock *rwlock) attribute_hidden;
extern long __sclib_futex_wait(int *ptr, int val)
#if !defined SHARED && !defined IS_IN_libpthread
	weak_function
#endif
;
extern long __sclib_futex_wake(int *ptr, int val)
#if !defined SHARED && !defined IS_IN_libpthread
	weak_function
#endif
;
extern void __sclib_schedule(int sysid, struct syscall_entry *entry)
#if !defined SHARED && !defined IS_IN_libpthread
	weak_function
#endif
;

extern long __sclib_mutex_auto_init(struct __sclib_mutex_auto *mutex, int kind);
extern long __sclib_mutex_auto_init_internal(struct __sclib_mutex_auto *mutex, int kind);

extern long __sclib_mutex_auto_reinit(struct __sclib_mutex_auto *mutex);
extern long __sclib_mutex_auto_reinit_internal(struct __sclib_mutex_auto *mutex);

extern void __sclib_mutex_auto_destroy(struct __sclib_mutex_auto *mutex);
extern void __sclib_mutex_auto_destroy_internal(struct __sclib_mutex_auto *mutex);

extern long __sclib_mutex_auto_lock(struct __sclib_mutex_auto *mutex);
extern long __sclib_mutex_auto_lock_internal(struct __sclib_mutex_auto *mutex);

extern long __sclib_mutex_auto_trylock(struct __sclib_mutex_auto *mutex);
extern long __sclib_mutex_auto_trylock_internal(struct __sclib_mutex_auto *mutex);

extern long __sclib_mutex_auto_unlock(struct __sclib_mutex_auto *mutex);
extern long __sclib_mutex_auto_unlock_internal(struct __sclib_mutex_auto *mutex);

extern void __sclib_kthread_init(struct kpthread *kpd) attribute_hidden;
extern void __sclib_thread_init(struct pthread *pd, struct kpthread *kpd) attribute_hidden;

#if defined NOT_IN_libc && defined IS_IN_libpthread
hidden_proto (__sclib_futex_wait)
hidden_proto (__sclib_futex_wake)
hidden_proto (__sclib_schedule)
#endif

#endif
