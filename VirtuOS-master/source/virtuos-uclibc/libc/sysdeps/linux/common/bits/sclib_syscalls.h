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

#ifndef _SCLIB_SYSCALLS_H
#define _SCLIB_SYSCALLS_H

#include <inttypes.h>
#include <sys/types.h>
#include <libc-symbols.h>
#include <stdio.h>

#include <bits/sclib.h>

#define SCLIB_CLONE_THREAD	0x7FFFFFFFL

long __internal_sys_read(int fd, void *buf, size_t count);
libc_hidden_proto(__internal_sys_read)

long __internal_sys_write(int fd, const void *buf, size_t count);
libc_hidden_proto(__internal_sys_write)

long __internal_sys_open(const char * file, int flags, int mode);
libc_hidden_proto(__internal_sys_open)

long __internal_sys_close(int fd);
libc_hidden_proto(__internal_sys_close)

long __internal_sys_clone_begin(long flags);
libc_hidden_proto(__internal_sys_clone_begin)

static inline void __internal_sys_clone_thread(void)
{
	sclib_memory_prealloc_init();
	/* Better way to handle error? */
	if (SCLIB_IS_ERR(sclib_efds_open(false))) {
		fprintf(stderr, "ERROR: Cannot initialize EFDS!\n");
		exit(1);
	}
}

void __internal_sys_clone_child(long param);
libc_hidden_proto(__internal_sys_clone_child)

long __internal_sys_clone_parent(long ret, long param);
libc_hidden_proto(__internal_sys_clone_parent)

long __internal_sys_fork(void);
libc_hidden_proto(__internal_sys_fork)

#endif /* !_SCLIB_SYSCALLS_H */
