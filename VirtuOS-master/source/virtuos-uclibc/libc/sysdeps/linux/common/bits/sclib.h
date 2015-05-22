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

#ifndef _SCLIB_H
#define _SCLIB_H 1

#include <sys/mman.h>
#include <libc-symbols.h>
#include <bits/uClibc_page.h>
#include <../libc/termios/kernel_termios.h>
#include <scheduleP.h>
#include "sclib_public.h"
#include "_syscall_queue.h"
#include "_perfctr_ioctl.h"

/* Not declared anywhere currently */
#if !defined(F_SETOWN_EX) && !defined(F_GETOWN_EX)
struct f_owner_ex {
	int type;
	__kernel_pid_t pid;
};
#endif
#ifndef F_SETOWN_EX
# define F_SETOWN_EX 15
#endif
#ifndef F_GETOWN_EX
# define F_GETOWN_EX 16
#endif

#define SCLIB_WAIT_ITERATIONS			4000
#define SCLIB_NUM_KTHREADS				18
#define SCLIB_MAX_KTHREADS				1024
#define SCLIB_MEMORY_ALIGN				(2 * sizeof(size_t))
#define SCLIB_MEMORY_MAGIC_ALLOC		0xAAA00AAA
#define SCLIB_MEMORY_MAGIC_FREE			0xFFF00FFF

#define SCLIB_MEMORY_PREALLOC

#define SCLIB_WAIT_RESULT_DELAY			__asm__ __volatile__ ("pause")

struct sclib_memory_block_s;
typedef struct sclib_memory_block_s sclib_memory_block_t;

typedef struct sclib_memory_binfo_s {
	size_t magic;
	size_t size;
} sclib_memory_binfo_t;

struct sclib_memory_block_s {
	sclib_memory_binfo_t block;
	sclib_memory_list_t list;
};

#ifdef __cplusplus
extern "C" {
#endif

void sclib_init(void);
libc_hidden_proto(sclib_init)

void sclib_terminate(void);
libc_hidden_proto(sclib_terminate)

void sclib_memory_init(void);
libc_hidden_proto(sclib_memory_init)

#ifdef SCLIB_MEMORY_PREALLOC
# ifdef __UCLIBC_HAS_TLS__
extern __thread sclib_memory_block_t *sclib_memptr[SYSCALL_SYSIDS];
# else
#  error "Need TLS support for SCLIB thread data"
# endif
static inline void sclib_memory_prealloc_init(void)
{
	size_t sysid;
	for (sysid = 0; sysid < SYSCALL_SYSIDS; sysid++)
		sclib_memptr[sysid] = NULL;
}
void sclib_memory_prealloc_exit(void);
libc_hidden_proto(sclib_memory_prealloc_exit)
#else
static inline void sclib_memory_prealloc_init(void) {}
static inline void sclib_memory_prealloc_exit(void) {}
#endif

void sclib_file_init(sclib_file_table_t *file);
libc_hidden_proto(sclib_file_init)

void sclib_file_exec(sclib_file_table_t *file);
libc_hidden_proto(sclib_file_exec)

long sclib_fds_save(void);
libc_hidden_proto(sclib_fds_save)

long sclib_fd_mmap(void);
libc_hidden_proto(sclib_fd_mmap)

long sclib_fd_open(void);
libc_hidden_proto(sclib_fd_open)

void sclib_fd_close(void);
libc_hidden_proto(sclib_fd_close)

char *sclib_get_path(char *abspath, const char *path, int *sysid, size_t *sz);
libc_hidden_proto(sclib_get_path)

long sclib_efds_open(bool new_process);
libc_hidden_proto(sclib_efds_open)

void sclib_efds_close(void);
libc_hidden_proto(sclib_efds_close)

extern struct syscall_queue *sclib_rqueue;
libc_hidden_proto(sclib_rqueue)

extern size_t sclib_wait_iterations;
libc_hidden_proto(sclib_wait_iterations);

static inline void sclib_queue_init(struct syscall_queue *queue)
{
	size_t i;

	queue->alloc_head.index = 0;
	queue->alloc_head.stamp = 0;
	queue->alloc_tail = queue->alloc_head;
	queue->free_head.index = 1;
	queue->free_head.stamp = 0;
	queue->free_tail.index = SYSCALL_MAX_PTHREADS-1;
	queue->free_tail.stamp = 0;
	queue->next[0].index = SYSCALL_NULL_ENTRY;
	queue->next[0].stamp = 0;
	for (i = 1; i < SYSCALL_MAX_PTHREADS-1; i++) {
		queue->next[i].index = i + 1;
		queue->next[i].stamp = 0;
	}
	queue->next[SYSCALL_MAX_PTHREADS-1].index = SYSCALL_NULL_ENTRY;
	queue->next[SYSCALL_MAX_PTHREADS-1].stamp = 0;
	queue->waiters = 0;
	queue->nkthreads = 1;
}

static inline void sclib_init_minimal(void)
{
	long ret, fd;

	fd = SCLIB_LOCAL_CALL(open, 2, "/dev/syscall_service", O_RDWR);
	if (SCLIB_IS_ERR(fd)) {
		fprintf(stderr, "Cannot open /dev/syscall_service!\n");
		exit(1);
	}
	ret = SCLIB_LOCAL_CALL(mmap, 6, NULL, SYSCALL_QUEUE_PAGES * PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (SCLIB_IS_ERR(ret)) {
		fprintf(stderr, "Cannot mmap ready queue!\n");
		exit(1);
	}
	SCLIB_LOCAL_CALL(close, 1, fd);
	sclib_rqueue = (struct syscall_queue *) ret;
	sclib_queue_init(sclib_rqueue);
}

static inline bool sclib_ioctl_open(unsigned long cmd)
{
	return (cmd == PERFCTR_IOCTL_CREAT || cmd == PERFCTR_IOCTL_OPEN);
}

static inline void sclib_ioctl_decode(unsigned long cmd, unsigned *dir, size_t *size)
{
	switch (cmd) {
		case TCGETS:
		case TIOCGLCKTRMIOS:
			*dir = _IOC_READ;
			*size = sizeof(struct __kernel_termios);
			break;
		case TCSETS:
		case TCSETSW:
		case TCSETSF:
		case TIOCSLCKTRMIOS:
			*dir = _IOC_WRITE;
			*size = sizeof(struct __kernel_termios);
			break;
		case TCGETA:
			*dir = _IOC_READ;
			*size = sizeof(struct termio);
			break;
		case TCSETA:
		case TCSETAW:
		case TCSETAF:
			*dir = _IOC_WRITE;
			*size = sizeof(struct termio);
			break;
		case TIOCGWINSZ:
			*dir = _IOC_READ;
			*size = sizeof(struct winsize);
			break;
		case TIOCSWINSZ:
			*dir = _IOC_WRITE;
			*size = sizeof(struct winsize);
			break;
		case TIOCINQ: /* FIONREAD, SIOCINQ */
		case TIOCOUTQ: /* SIOCOUTQ */
		case TIOCGPGRP:
		case TIOCGSID:
		case TIOCGETD:
		case TIOCMGET:
		case TIOCGSOFTCAR:
		case FIOGETOWN:
		case SIOCATMARK:
			*dir = _IOC_READ;
			*size = sizeof(int);
			break;
		case TIOCSPGRP:
		case TIOCSETD:
		case TIOCPKT:
		case TIOCMSET:
		case TIOCMBIC:
		case TIOCMBIS:
		case TIOCSSOFTCAR:
		case FIONBIO:
		case FIOASYNC:
		case FIOSETOWN:
			*dir = _IOC_WRITE;
			*size = sizeof(int);
			break;
		case TIOCSTI:
			*dir = _IOC_WRITE;
			*size = sizeof(char);
			break;
		case FIOQSIZE:
			*dir = _IOC_READ;
			*size = sizeof(loff_t);
			break;
		case SIOCSPGRP:
			*dir = _IOC_WRITE;
			*size = sizeof(pid_t);
			break;
		case SIOCGPGRP:
			*dir = _IOC_READ;
			*size = sizeof(pid_t);
			break;
		case SIOCGSTAMP:
			*dir = _IOC_READ;
			*size = sizeof(struct timeval);
			break;
		case SIOCGSTAMPNS:
			*dir = _IOC_READ;
			*size = sizeof(struct timespec);
			break;
		case FIOCLEX:
		case FIONCLEX:
			*dir = 0;
			*size = 0;
			break;
		default:
			*dir = _IOC_DIR(cmd);
			*size = _IOC_SIZE(cmd);
			break;
	}
}

static inline void sclib_fcntl_decode(unsigned cmd, unsigned *dir, size_t *size)
{
	switch (cmd) {
		case F_GETLK:
			*dir = _IOC_READ | _IOC_WRITE;
			*size = sizeof(struct flock);
			break;
		case F_SETLK:
		case F_SETLKW:
			*dir = _IOC_WRITE;
			*size = sizeof(struct flock);
			break;
		case F_GETOWN_EX:
			*dir = _IOC_READ;
			*size = sizeof(struct f_owner_ex);
			break;
		case F_SETOWN_EX:
			*dir = _IOC_WRITE;
			*size = sizeof(struct f_owner_ex);
			break;
		default:
			*dir = _IOC_NONE;
			*size = 0;
			break;
	}
}

static inline void __sclib_queue_add(struct syscall_queue *queue, struct pthread *thread)
{
	struct pthread *result;
	size_t idx;

	idx = syscall_queue_dequeue(queue->next, queue->entries, &queue->free_head,
		&queue->free_tail, &result, SYSCALL_MAX_PTHREADS, false);
	if ((ssize_t) idx < 0) {
		fprintf(stderr, "ERROR: ready queue failure (5)!\n");
		exit(1);
	}
	queue->entries[idx] = thread;
	if (syscall_queue_enqueue(queue->next, &queue->alloc_tail, idx, SYSCALL_MAX_PTHREADS, false) != 0) {
		fprintf(stderr, "ERROR: ready queue failure (6)!\n");
		exit(1);
	}
	if (VOLATILE_READ(queue->waiters) != 0) {
		SCLIB_LOCAL_CALL(rqueue_wake, 1, 1);
	}
}

static inline struct pthread *__sclib_queue_remove(struct syscall_queue *queue, bool block)
{
	struct pthread *result;
	size_t idx;
	size_t counter = sclib_wait_iterations;

again:
	idx = syscall_queue_dequeue(queue->next, queue->entries, &queue->alloc_head, &queue->alloc_tail, &result, SYSCALL_MAX_PTHREADS, false);
	if (idx == SYSCALL_ERROR_ENTRY) {
		fprintf(stderr, "ERROR: ready queue failure (7)!\n");
		exit(1);
	}
	if (idx == SYSCALL_NULL_ENTRY) {
		if (!block)
			return NULL;
		/* Spin a little bit. */
		if (counter != 0) {
			SCLIB_WAIT_RESULT_DELAY;
			counter--;
			goto again;
		}
		while ((long) (idx = SCLIB_LOCAL_CALL(rqueue_wait, 2, queue, &result)) == -EINTR) {}
		if (SCLIB_IS_ERR(idx)) {
			fprintf(stderr, "ERROR: ready queue failure in kernel (7)!\n");
			exit(1);
		}
	}
	if (syscall_queue_enqueue(queue->next, &queue->free_tail, idx, SYSCALL_MAX_PTHREADS, false) != 0) {
		fprintf(stderr, "ERROR: ready queue failure (8)!\n");
		exit(1);
	}
#if 0
	if (queue->waiters != 0 && syscall_queue_check(queue->next, &queue->alloc_head, &queue->alloc_tail, SYSCALL_MAX_PTHREADS) == 0)
		SCLIB_LOCAL_CALL(rqueue_wake, 1, 1);
#endif
	return result;
}

static inline void __sclib_queue_single_remove(struct syscall_queue *queue, int sysid, unsigned int id, struct syscall_entry *entry)
{
	struct pthread *result;
	size_t idx;

	idx = SCLIB_LOCAL_CALL(rqueue_wait_notify, 5, queue, sysid, id, entry, &result);
	if (idx != SYSCALL_MAX_PTHREADS) {
		if ((long) idx == -EINTR) {
			while ((long) (idx = SCLIB_LOCAL_CALL(rqueue_wait, 2, queue, &result)) == -EINTR) {}
		}
		if (SCLIB_IS_ERR(idx)) {
			fprintf(stderr, "ERROR: ready queue failure in kernel (7)!\n");
			exit(1);
		}
		if (syscall_queue_enqueue(queue->next, &queue->free_tail, idx, SYSCALL_MAX_PTHREADS, false) != 0) {
			fprintf(stderr, "ERROR: ready queue failure (8)!\n");
			exit(1);
		}
	}
#if 0
	if (queue->waiters != 0 && syscall_queue_check(queue->next, &queue->alloc_head, &queue->alloc_tail, SYSCALL_MAX_PTHREADS) == 0)
		SCLIB_LOCAL_CALL(rqueue_wake, 1, 1);
#endif
}

static inline void sclib_schedule_single(int sysid, struct syscall_entry *entry)
{
	unsigned int id;
	size_t counter = sclib_wait_iterations;

	do {
		id = VOLATILE_READ(entry->id);
		if (id == SYSCALL_ENTRY_DONE) /* Completed. */
			return;
		SCLIB_WAIT_RESULT_DELAY;
	} while (--counter != 0);

	id = VOLATILE_READ(entry->id);
	if (id == SYSCALL_ENTRY_DONE) /* Completed. */
		return;
	__sclib_queue_single_remove(sclib_rqueue, sysid, id, entry);
}

#ifdef __cplusplus
}
#endif

#endif /* !_SCLIB_H */
