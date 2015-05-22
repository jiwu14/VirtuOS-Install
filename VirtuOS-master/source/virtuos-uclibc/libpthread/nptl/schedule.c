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

#include <ucontext.h>
#include <list.h>
#include <lowlevellock.h>
#include <descr.h>
#include <stdio.h>
#include <sys/mman.h>
#include <scheduleP.h>
#include <atomic.h>

#include <bits/sclib.h>

struct __sclib_futex_queue {
	list_t list;
	int *value;
	struct pthread *thread;
	unsigned int counter;
};

#define __SCLIB_PAGE_SIZE			4096UL
#define __SCLIB_QUEUES_THRESHOLD	1024

#define __SCLIB_FUTEX_TABLE_SIZE	256

list_t __futex_table[__SCLIB_FUTEX_TABLE_SIZE];
static struct syscall_queue __sclib_queues;
static struct __sclib_mutex __futex_table_lock;
static unsigned long __sclib_queues_num = 0;
struct syscall_queue *__nptl_rqueue;

#define __SCLIB_PTHREAD_BLOCKED_QUEUE	(__SCLIB_PTHREAD_BLOCKED + 0)
#define __SCLIB_PTHREAD_BLOCKED_COND	(__SCLIB_PTHREAD_BLOCKED + 1)
#define __SCLIB_PTHREAD_BLOCKED_FUTEX	(__SCLIB_PTHREAD_BLOCKED + 2)
#define __SCLIB_PTHREAD

#define SQUEUE_NULL	\
	MAP_FAILED
#define SQUEUE_ALLOC()	\
	mmap(0, sizeof(struct syscall_queue), PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
#define SQUEUE_FREE(a)	\
	munmap((a), sizeof(struct syscall_queue))

#if 0

static inline unsigned int __sclib_wq_create(void)
{
	long ret;
	INTERNAL_SYSCALL_DECL(err);
	ret = INTERNAL_SYSCALL(syscall_service_wq_create, err, 0);
	if (INTERNAL_SYSCALL_ERROR_P(ret, err))
		ret = -INTERNAL_SYSCALL_ERRNO(ret, err);
	return ret;
}

static inline long __sclib_wq_destroy(unsigned int descriptor)
{
	long ret;
	INTERNAL_SYSCALL_DECL(err);
	ret = INTERNAL_SYSCALL(syscall_service_wq_destroy, err, 1, descriptor);
	if (INTERNAL_SYSCALL_ERROR_P(ret, err))
		ret = -INTERNAL_SYSCALL_ERRNO(ret, err);
	return ret;
}

static inline void __sclib_wq_wake(unsigned int descriptor)
{
	long ret;
	INTERNAL_SYSCALL_DECL(err);
	ret = INTERNAL_SYSCALL(syscall_service_wq_wake, err, 1, descriptor);
	if (INTERNAL_SYSCALL_ERROR_P(ret, err)) {
		fprintf(stderr, "Cannot wake up from a waiting queue\n");
		exit(1);
	}
}

static inline size_t __sclib_wq_wait(struct syscall_queue *queue,
	struct pthread **result)
{
	long ret;
	INTERNAL_SYSCALL_DECL(err);
	ret = INTERNAL_SYSCALL(syscall_service_wq_wait, err, 2, queue, result);
	if (INTERNAL_SYSCALL_ERROR_P(ret, err)) {
		fprintf(stderr, "Cannot waint on a waiting queue\n");
		exit(1);
	}
	return ret;
}
#endif

static bool __sclib_queue_add_mark(struct syscall_queue *queue, void *thread, bool mark)
{
	void *result;
	size_t idx, res;

	idx = syscall_queue_dequeue(queue->next, queue->entries, &queue->free_head,
		&queue->free_tail, &result, SYSCALL_MAX_PTHREADS, false);
	if ((ssize_t) idx < 0) {
		fprintf(stderr, "ERROR: ready queue failure (1)!\n");
		exit(1);
	}
	queue->entries[idx] = thread;
	if ((res = syscall_queue_enqueue(queue->next, &queue->alloc_tail, idx, SYSCALL_MAX_PTHREADS, mark)) != 0) {
		if (res == SYSCALL_NULL_ENTRY && syscall_queue_enqueue(queue->next,
			&queue->free_tail, idx, SYSCALL_MAX_PTHREADS, false) == 0) {
			return false;
		}
		fprintf(stderr, "ERROR: ready queue failure (2)!\n");
		exit(1);
	}
	return true;
}

static void *__sclib_queue_remove_mark(struct syscall_queue *queue, bool mark)
{
	void *result;
	size_t idx;

	idx = syscall_queue_dequeue(queue->next, queue->entries, &queue->alloc_head,
	        &queue->alloc_tail, &result, SYSCALL_MAX_PTHREADS, mark);
	if (idx == SYSCALL_ERROR_ENTRY) {
		fprintf(stderr, "ERROR: ready queue failure (3)!\n", queue);
		exit(1);
	}
	if (idx == SYSCALL_NULL_ENTRY)
		return NULL;
	if (syscall_queue_enqueue(queue->next, &queue->free_tail, idx, SYSCALL_MAX_PTHREADS, false) != 0) {
		fprintf(stderr, "ERROR: ready queue failure (4)!\n");
		exit(1);
	}
	return result;
}

static inline void __sclib_unblock(struct pthread *thread)
{
	thread->state = __SCLIB_PTHREAD_RUNNING;
	__sclib_queue_add(__nptl_rqueue, thread);
}

static void __sclib_enqueue(struct pthread *thread)
{
	struct syscall_queue *queue;
	struct __sclib_futex_queue *futex;
	struct __sclib_mutex *mutex;
	syscall_entry_t *entry;
	unsigned int id;

	queue = KTHREAD_GETMEM(KTHREAD_SELF, current_queue);
	if (queue != NULL) {
		if (thread->state >= __SCLIB_PTHREAD_BLOCKED) {
			if (thread->state == __SCLIB_PTHREAD_BLOCKED_QUEUE) {
				if (!__sclib_queue_add_mark(queue, thread, true))
					__sclib_unblock(thread);
			} else if (thread->state == __SCLIB_PTHREAD_BLOCKED_FUTEX) {
				futex = (struct __sclib_futex_queue *) queue;
				if (atomic_decrement_and_test(&futex->counter)) {
					__sclib_mutex_lock(&__futex_table_lock);
					list_del(&futex->list);
					__sclib_mutex_unlock(&__futex_table_lock);
					free(futex);
					__sclib_unblock(thread);
				}
			} else {
				__sclib_queue_add_mark(queue, thread, false);
				mutex = KTHREAD_GETMEM(KTHREAD_SELF, current_mutex);
				__sclib_mutex_unlock(mutex);
			}
		} else {
			__sclib_queue_add(queue, thread);
		}
	} else {
		entry = KTHREAD_GETMEM(KTHREAD_SELF, current_entry);
		do {
			id = VOLATILE_READ(entry->id);
			if (id == SYSCALL_ENTRY_DONE) { /* Already completed. */
				__sclib_queue_add(__nptl_rqueue, entry->pd);
				break;
			}
		} while (!__sync_bool_compare_and_swap(&entry->id, id, id + SYSCALL_ENTRY_RQUEUE));
	}
}

static void __sclib_swapcontext(struct pthread *from, ucontext_t *to)
{
	struct pthread *thread;
	ucontext_t *prev;

	prev = swapcontextp(&from->context, to);
	KTHREAD_SETMEM(KTHREAD_SELF, header.tcb, from);
	if (prev == NULL) /* Came from __sclib_thread_loop(). */
		return;
	thread = container_of(prev, struct pthread, context);
	__sclib_enqueue(thread);
}

attribute_protected
#if !defined SHARED && !defined IS_IN_libpthread
weak_function
#endif
void __sclib_schedule(int sysid, struct syscall_entry *entry)
{
	struct pthread *thread;
	KTHREAD_SETMEM(KTHREAD_SELF, current_queue, NULL);
	KTHREAD_SETMEM(KTHREAD_SELF, current_entry, entry);
	thread = __sclib_queue_remove(__nptl_rqueue, false);
	__sclib_swapcontext(THREAD_SELF, (thread != NULL) ? &thread->context : &KTHREAD_SELF->wait_context);
}
hidden_def(__sclib_schedule)

static inline void __sclib_block(struct pthread *pd, size_t state)
{
	struct pthread *thread;
	pd->state = state;
	thread = __sclib_queue_remove(__nptl_rqueue, false);
	if (thread != NULL) {
		thread->state = __SCLIB_PTHREAD_RUNNING;
		__sclib_swapcontext(pd, &thread->context);
		return;
	}
	__sclib_swapcontext(pd, &KTHREAD_SELF->wait_context);
}

attribute_hidden
void __sclib_schedule_init(struct syscall_queue *rqueue)
{
	size_t i;

	sclib_queue_init(&__sclib_queues);
	__nptl_rqueue = rqueue;
	if (__sclib_mutex_init(&__futex_table_lock, __SCLIB_MUTEX_NORMAL) != 0) {
		fprintf(stderr, "Cannot initialize futex table lock!\n");
		exit(1);
	}
	for (i = 0; i < __SCLIB_FUTEX_TABLE_SIZE; i++) {
		INIT_LIST_HEAD(&__futex_table[i]);
	}
	__sync_synchronize();
}

attribute_hidden
void __sclib_initial_switch(struct pthread *from, struct pthread *to)
{
	KTHREAD_SETMEM(KTHREAD_SELF, current_queue, __nptl_rqueue);
	__sclib_swapcontext(from, &to->context);
}

attribute_hidden
void __sclib_initial_add(struct pthread *thread)
{
	__sclib_queue_add(__nptl_rqueue, thread);
}

attribute_hidden
void __sclib_yield(void)
{
	struct pthread *thread;
	thread = __sclib_queue_remove(__nptl_rqueue, false);
	if (thread != NULL) {
		thread->state = __SCLIB_PTHREAD_RUNNING;
		KTHREAD_SETMEM(KTHREAD_SELF, current_queue, __nptl_rqueue);
		__sclib_swapcontext(THREAD_SELF, &thread->context);
	}
}

static struct syscall_queue *__sclib_alloc_queue(void)
{
	struct syscall_queue *queue;

	queue = __sclib_queue_remove_mark(&__sclib_queues, false);
	if (!queue) {
		queue = SQUEUE_ALLOC();
		if (queue == SQUEUE_NULL)
			return NULL;
		sclib_queue_init(queue);
	} else {
		atomic_decrement(&__sclib_queues_num);
	}
	return queue;
}

static void __sclib_free_queue(struct syscall_queue *queue)
{
	if (VOLATILE_READ(__sclib_queues_num) >= __SCLIB_QUEUES_THRESHOLD) {
		SQUEUE_FREE(queue);
		return;
	}
	atomic_increment(&__sclib_queues_num);
#ifdef SYSCALL_DEBUG
	if (syscall_queue_check(queue->next, &queue->alloc_head, &queue->alloc_tail, SYSCALL_MAX_PTHREADS) != SYSCALL_NULL_ENTRY) {
		fprintf(stderr, "Invalid use of POSIX locks!\n");
		exit(1);
	}
#endif
	__sclib_queue_add_mark(&__sclib_queues, queue, false);
}

static inline long __sclib_lazy_queue(struct syscall_queue **pqueue)
{
	struct syscall_queue *queue;

	if (*pqueue == NULL) {
		if ((queue = __sclib_alloc_queue()) == NULL)
			return ENOMEM;
		if (atomic_compare_and_exchange_bool_acq(pqueue,
			queue, NULL)) {
			__sclib_free_queue(queue);
		}
	}
	return 0;
}

long
attribute_protected
__sclib_mutex_auto_init(struct __sclib_mutex_auto *mutex, int kind)
{
	mutex->kind = kind;
	mutex->recur_count = 0;
	mutex->owner = NULL;
	mutex->value = 0;
	__sync_synchronize();
	return 0;
}
INTDEF(__sclib_mutex_auto_init)

void
attribute_protected
__sclib_mutex_auto_destroy(struct __sclib_mutex_auto *mutex)
{
	struct syscall_queue *queue;
	queue = (struct syscall_queue *)
		(VOLATILE_READ(mutex->value) & ~(__SCLIB_PAGE_SIZE - 1));
	if (queue != NULL)
		__sclib_free_queue(queue);
}
INTDEF(__sclib_mutex_auto_destroy)

long
attribute_protected
__sclib_mutex_auto_reinit(struct __sclib_mutex_auto *mutex)
{
	__sclib_mutex_auto_destroy(mutex);
	mutex->recur_count = 0;
	mutex->owner = NULL;
	mutex->value = 0;
	__sync_synchronize();
	return 0;
}
INTDEF(__sclib_mutex_auto_reinit)

static inline long __sclib_get_queue(unsigned long *pvalue, unsigned long value,
	struct syscall_queue **qptr)
{
	struct syscall_queue *queue, *nqueue;
	unsigned long oldvalue;

	queue = (struct syscall_queue *) (value & ~(__SCLIB_PAGE_SIZE - 1));
	if (queue != NULL) {
		*qptr = queue;
		return 0;
	}

	/* Allocate a queue. */
	if ((nqueue = __sclib_alloc_queue()) == NULL)
		return ENOMEM;

	while ((oldvalue = atomic_compare_and_exchange_val_acq(pvalue,
			value + (unsigned long) nqueue, value)) != value) {
		value = oldvalue;
		queue = (struct syscall_queue *) (value & ~(__SCLIB_PAGE_SIZE - 1));
		if (queue != NULL) {
			__sclib_free_queue(nqueue);
			*qptr = queue;
			return 0;
		}
	}

	*qptr = nqueue;
	return 0;
}

long
attribute_protected
__sclib_mutex_auto_lock(struct __sclib_mutex_auto *mutex)
{
	struct pthread *self = THREAD_SELF;
	struct syscall_queue *queue;
	unsigned long value;
	long err;

	if (mutex->kind == __SCLIB_MUTEX_RECURSIVE && mutex->owner == self) {
		mutex->recur_count++;
		return 0;
	}
	value = atomic_exchange_and_add(&mutex->value, 1);
	if ((value & (__SCLIB_PAGE_SIZE - 1)) != 0) {
		if ((err = __sclib_get_queue(&mutex->value, value + 1, &queue)) != 0)
			return err;
		KTHREAD_SETMEM(KTHREAD_SELF, current_queue, queue);
		__sclib_block(THREAD_SELF, __SCLIB_PTHREAD_BLOCKED_QUEUE);
	}
	mutex->recur_count++;
	mutex->owner = self;
	return 0;
}
INTDEF(__sclib_mutex_auto_lock)

long
attribute_protected
__sclib_mutex_auto_trylock(struct __sclib_mutex_auto *mutex)
{
	struct pthread *self = THREAD_SELF;
	unsigned long value;

	if (mutex->kind == __SCLIB_MUTEX_RECURSIVE && mutex->owner == self) {
		mutex->recur_count++;
		return 0;
	}
	do {
		value = VOLATILE_READ(mutex->value);
		if ((value & (__SCLIB_PAGE_SIZE - 1)) != 0)
			return EBUSY;
	} while (atomic_compare_and_exchange_bool_acq(&mutex->value,
		value + 1, value));
	mutex->recur_count++;
	mutex->owner = self;
	return 0;
}
INTDEF(__sclib_mutex_auto_trylock)

long
attribute_protected
__sclib_mutex_auto_unlock(struct __sclib_mutex_auto *mutex)
{
	struct pthread *thread;
	struct syscall_queue *queue;
	unsigned long value, newvalue, counter;
	long err;

	if (--mutex->recur_count != 0)
		return 0;
	mutex->owner = NULL;

	do {
		value = VOLATILE_READ(mutex->value);
		newvalue = value - 1;
		counter = newvalue & (__SCLIB_PAGE_SIZE - 1);
		if (counter == 0)
			newvalue = 0;
	} while (atomic_compare_and_exchange_bool_acq(&mutex->value,
		newvalue, value));

	if (counter != 0) {
		if ((err = __sclib_get_queue(&mutex->value, newvalue, &queue)) != 0)
			return err;
		thread = __sclib_queue_remove_mark(queue, true);
		if (thread)
			__sclib_unblock(thread);
	} else {
		queue = (struct syscall_queue *) (value - 1);
		if (queue != NULL)
			__sclib_free_queue(queue);
	}

	return 0;
}
INTDEF(__sclib_mutex_auto_unlock)

attribute_hidden
long __sclib_mutex_init(struct __sclib_mutex *mutex, int kind)
{
	mutex->counter = 0;
	mutex->kind = kind;
	mutex->recur_count = 0;
	mutex->owner = NULL;
	mutex->queue = NULL;
	__sync_synchronize();
	return 0;
}

attribute_hidden
long __sclib_mutex_reinit(struct __sclib_mutex *mutex)
{
	mutex->counter = 0;
	mutex->recur_count = 0;
	mutex->owner = NULL;
	if (mutex->queue)
		sclib_queue_init(mutex->queue);
	__sync_synchronize();
	return 0;
}

attribute_hidden
void __sclib_mutex_destroy(struct __sclib_mutex *mutex)
{
	if (mutex->queue)
		__sclib_free_queue(mutex->queue);
}

attribute_hidden
long __sclib_mutex_lock(struct __sclib_mutex *mutex)
{
	struct pthread *self = THREAD_SELF;
	long err;

	if (mutex->kind == __SCLIB_MUTEX_RECURSIVE && mutex->owner == self) {
		mutex->recur_count++;
		return 0;
	}
	if (atomic_increment_val(&mutex->counter) != 1) {
		if ((err = __sclib_lazy_queue(&mutex->queue)) != 0)
			return err;
		KTHREAD_SETMEM(KTHREAD_SELF, current_queue, mutex->queue);
		__sclib_block(THREAD_SELF, __SCLIB_PTHREAD_BLOCKED_QUEUE);
	}
	mutex->recur_count++;
	mutex->owner = self;
	return 0;
}

attribute_hidden
long __sclib_mutex_trylock(struct __sclib_mutex *mutex)
{
	struct pthread *self = THREAD_SELF;
	unsigned int counter;

	if (mutex->kind == __SCLIB_MUTEX_RECURSIVE && mutex->owner == self) {
		mutex->recur_count++;
		return 0;
	}
	do {
		counter = mutex->counter;
		if (counter != 0)
			return EBUSY;
	} while (atomic_compare_and_exchange_bool_acq(&mutex->counter,
		counter + 1, counter));
	mutex->recur_count++;
	mutex->owner = self;
	return 0;
}

attribute_hidden
long __sclib_mutex_unlock(struct __sclib_mutex *mutex)
{
	struct pthread *thread;
	long err;

	if (--mutex->recur_count != 0)
		return 0;
	mutex->owner = NULL;
	if (!atomic_decrement_and_test(&mutex->counter)) {
		if ((err = __sclib_lazy_queue(&mutex->queue)) != 0)
			return err;
		thread = __sclib_queue_remove_mark(mutex->queue, true);
		if (thread)
			__sclib_unblock(thread);
	}
	return 0;
}

static inline size_t __sclib_futex_hash(int *ptr)
{
	size_t val = (size_t) ptr;
	return (val >> 4) % __SCLIB_FUTEX_TABLE_SIZE;
}

attribute_protected
#if !defined SHARED && !defined IS_IN_libpthread
weak_function
#endif
long __sclib_futex_wait(int *ptr, int val)
{
	struct __sclib_futex_queue *futex;
	struct pthread *thread = THREAD_SELF;
	size_t idx;

	futex = malloc(sizeof(struct __sclib_futex_queue));
	if (futex == NULL)
		return ENOMEM;
	futex->counter = 0x80000000;
	futex->value = ptr;
	futex->thread = thread;
	idx = __sclib_futex_hash(ptr);
	__sclib_mutex_lock(&__futex_table_lock);
	if (*ptr != val) {
		__sclib_mutex_unlock(&__futex_table_lock);
		free(futex);
		return 0;
	}
	list_add(&futex->list, &__futex_table[idx]);
	__sclib_mutex_unlock(&__futex_table_lock);
	KTHREAD_SETMEM(KTHREAD_SELF, current_queue, futex);
	__sclib_block(thread, __SCLIB_PTHREAD_BLOCKED_FUTEX);
	return 0;
}
hidden_def(__sclib_futex_wait)

attribute_protected
#if !defined SHARED && !defined IS_IN_libpthread
weak_function
#endif
long __sclib_futex_wake(int *ptr, int val)
{
	struct pthread *thread;
	struct __sclib_futex_queue *futex;
	size_t idx;
	list_t *entry, *p;

	idx = __sclib_futex_hash(ptr);
	__sclib_mutex_lock(&__futex_table_lock);
	list_for_each_safe(entry, p, &__futex_table[idx]) {
		futex = list_entry(entry, struct __sclib_futex_queue, list);
		if (futex->value == ptr && futex->counter > 1) {
			if (atomic_add_zero(&futex->counter, 0x80000001)) {
				list_del(&futex->list);
				thread = futex->thread;
				free(futex);
				__sclib_unblock(thread);
			}
			if (--val == 0)
				break;
		}
	}
	__sclib_mutex_unlock(&__futex_table_lock);
	return 0;
}
hidden_def(__sclib_futex_wake)

attribute_hidden
long __sclib_cond_init(struct __sclib_cond *cond)
{
	cond->queue = NULL;
	__sync_synchronize();
	return 0;
}

attribute_hidden
long __sclib_cond_wait(struct __sclib_cond *cond, struct __sclib_mutex *mutex)
{
	long err;
	if ((err = __sclib_lazy_queue(&cond->queue)) != 0)
		return err;
	KTHREAD_SETMEM(KTHREAD_SELF, current_queue, cond->queue);
	KTHREAD_SETMEM(KTHREAD_SELF, current_mutex, mutex);
	__sclib_block(THREAD_SELF, __SCLIB_PTHREAD_BLOCKED_COND);
	return __sclib_mutex_lock(mutex);
}

attribute_hidden
long __sclib_cond_signal(struct __sclib_cond *cond)
{
	struct pthread *thread;
	long err;
	if ((err = __sclib_lazy_queue(&cond->queue)) != 0)
		return err;
	thread = __sclib_queue_remove_mark(cond->queue, false);
	if (thread)
		__sclib_unblock(thread);
	return 0;
}

attribute_hidden
long __sclib_cond_broadcast(struct __sclib_cond *cond)
{
	struct pthread *thread;
	long err;
	if ((err = __sclib_lazy_queue(&cond->queue)) != 0)
		return err;
	while ((thread = __sclib_queue_remove_mark(cond->queue, false)) != NULL)
		__sclib_unblock(thread);
	return 0;
}

attribute_hidden
void __sclib_cond_destroy(struct __sclib_cond *cond)
{
	if (cond->queue)
		__sclib_free_queue(cond->queue);
}

attribute_hidden
long __sclib_sem_init(struct __sclib_sem *sem, unsigned int val)
{
	if ((sem->queue = __sclib_alloc_queue()) == NULL)
		return ENOMEM;
	sem->value = val;
	__sync_synchronize();
	return 0;
}

attribute_hidden
void __sclib_sem_destroy(struct __sclib_sem *sem)
{
	__sclib_free_queue(sem->queue);
}

attribute_hidden
long __sclib_sem_wait(struct __sclib_sem *sem)
{
	if (atomic_decrement_val(&sem->value) < 0) {
		KTHREAD_SETMEM(KTHREAD_SELF, current_queue, sem->queue);
		__sclib_block(THREAD_SELF, __SCLIB_PTHREAD_BLOCKED_QUEUE);
	}
	return 0;
}

attribute_hidden
long __sclib_sem_trywait(struct __sclib_sem *sem)
{
	long value;

	do {
		value = sem->value;
		if (value <= 0)
			return EAGAIN;
	} while (atomic_compare_and_exchange_bool_acq(&sem->value,
		value - 1, value));
	return 0;
}

attribute_hidden
long __sclib_sem_post(struct __sclib_sem *sem)
{
	struct pthread *thread;

	if (atomic_increment_val(&sem->value) <= 0) {
		thread = __sclib_queue_remove_mark(sem->queue, true);
		if (thread)
			__sclib_unblock(thread);
	}
	return 0;
}

attribute_hidden
long __sclib_rwlock_init(struct __sclib_rwlock *rwlock)
{
	long err;
	rwlock->readers = 0;
	rwlock->writer = 0;
	if ((err = __sclib_mutex_init(&rwlock->access_mutex, __SCLIB_MUTEX_NORMAL)) != 0)
		return err;
	return __sclib_mutex_init(&rwlock->wait_mutex, __SCLIB_MUTEX_NORMAL);
}

attribute_hidden
void __sclib_rwlock_destroy(struct __sclib_rwlock *rwlock)
{
	__sclib_mutex_destroy(&rwlock->access_mutex);
	__sclib_mutex_destroy(&rwlock->wait_mutex);
}

attribute_hidden
long __sclib_rwlock_rdlock(struct __sclib_rwlock *rwlock)
{
	__sclib_mutex_lock(&rwlock->wait_mutex);
	if (atomic_increment_val(&rwlock->readers) == 1) {
		__sclib_mutex_lock(&rwlock->access_mutex);
		rwlock->writer = 0;
	}
	__sclib_mutex_unlock(&rwlock->wait_mutex);
	return 0;
}

attribute_hidden
long __sclib_rwlock_tryrdlock(struct __sclib_rwlock *rwlock)
{
	long err;
	if ((err = __sclib_mutex_trylock(&rwlock->wait_mutex)) != 0)
		return err;
	if (atomic_increment_val(&rwlock->readers) == 1) {
		if ((err = __sclib_mutex_trylock(&rwlock->access_mutex)) != 0)
			atomic_decrement(&rwlock->readers);
		else
			rwlock->writer = 0;
	}
	__sclib_mutex_unlock(&rwlock->wait_mutex);
	return err;
}

attribute_hidden
long __sclib_rwlock_trywrlock(struct __sclib_rwlock *rwlock)
{
	long err;
	if ((err = __sclib_mutex_trylock(&rwlock->wait_mutex)) != 0)
		return err;
	if ((err = __sclib_mutex_trylock(&rwlock->access_mutex)) == 0)
		rwlock->writer = 1;
	__sclib_mutex_unlock(&rwlock->wait_mutex);
	return err;
}

attribute_hidden
long __sclib_rwlock_wrlock(struct __sclib_rwlock *rwlock)
{
	__sclib_mutex_lock(&rwlock->wait_mutex);
	__sclib_mutex_lock(&rwlock->access_mutex);
	rwlock->writer = 1;
	__sclib_mutex_unlock(&rwlock->wait_mutex);
	return 0;
}

attribute_hidden
void __sclib_rwlock_unlock(struct __sclib_rwlock *rwlock)
{
	if (rwlock->writer || atomic_decrement_and_test(&rwlock->readers))
		__sclib_mutex_unlock(&rwlock->access_mutex);
}

static void __sclib_exit_context(struct kpthread *kpd)
{
	struct pthread *pd = THREAD_SELF;

	/* Deallocate old thread */
	if (IS_DETACHED(pd)) {
		pd->tid = -1;
	} else {
		__sclib_sem_post(&pd->exit_sem);
	}
	pd = __sclib_queue_remove(__nptl_rqueue, true);
	setcontextp(&pd->context, &kpd->context);
}

static void __sclib_wait_context(struct kpthread *kpd)
{
	struct pthread *thread;
	__sclib_enqueue(THREAD_SELF);
	thread = __sclib_queue_remove(__nptl_rqueue, true);
	setcontextp(&thread->context, &kpd->wait_context);
}

attribute_hidden
void __sclib_kthread_init(struct kpthread *kpd)
{
	getcontext(&kpd->context);
	makecontext(&kpd->context, (void (*) (void)) __sclib_exit_context, 1, kpd);
	memcpy(&kpd->wait_context.uc_sigmask, &kpd->context.uc_sigmask, sizeof(kpd->context.uc_sigmask));
	memcpy(&kpd->wait_context.uc_mcontext, &kpd->context.uc_mcontext, sizeof(kpd->context.uc_mcontext));
	memcpy(&kpd->wait_context.uc_stack, &kpd->context.uc_stack, sizeof(kpd->context.uc_stack));
	memcpy(&kpd->wait_context.__fpregs_mem, &kpd->context.__fpregs_mem, sizeof(kpd->context.__fpregs_mem));
	makecontext(&kpd->wait_context, (void (*) (void)) __sclib_wait_context, 1, kpd);
}

attribute_hidden
void __sclib_thread_init(struct pthread *pd, struct kpthread *kpd)
{
	memcpy(&pd->context.uc_sigmask, &kpd->context.uc_sigmask, sizeof(kpd->context.uc_sigmask));
	memcpy(&pd->context.uc_mcontext, &kpd->context.uc_mcontext, sizeof(kpd->context.uc_mcontext));
	memcpy(&pd->context.__fpregs_mem, &kpd->context.__fpregs_mem, sizeof(kpd->context.__fpregs_mem));
	pd->state = __SCLIB_PTHREAD_RUNNING;
}
