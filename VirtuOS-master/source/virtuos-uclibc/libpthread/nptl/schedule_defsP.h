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

#ifndef __SCLIB_SCHEDULE_DEFS_P_H
#define __SCLIB_SCHEDULE_DEFS_P_H

struct syscall_queue;
struct pthread;

#define __SCLIB_MUTEX_NORMAL	0
#define __SCLIB_MUTEX_RECURSIVE	1

struct __sclib_mutex_auto {
	unsigned long value;
	struct pthread *owner;
	unsigned int kind; /* For compatibility with a static initializer. */
	unsigned int recur_count;
};

struct __sclib_mutex {
	struct syscall_queue *queue;
	struct pthread *owner;
	unsigned short kind; /* For compatibility with a static initializer. */
	unsigned short recur_count;
	unsigned int counter;
};

struct __sclib_sem {
	struct syscall_queue *queue;
	long value;
};

struct __sclib_rwlock {
	struct __sclib_mutex access_mutex;
	struct __sclib_mutex wait_mutex;
	unsigned char pad; /* For compatibility with a static initializer. */
	unsigned char writer;
	unsigned short readers;
};

struct __sclib_cond {
	struct syscall_queue *queue;
};

#endif
