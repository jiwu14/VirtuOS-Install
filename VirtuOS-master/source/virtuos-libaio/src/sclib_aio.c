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

#include "sclib_aio.h"

__attribute__ ((constructor))
	void aio_init(void)
{
	size_t i;
	for (i = 0; i < sizeof(sclib_aio.map) / sizeof(sclib_aio.map[0]); i++)
		sclib_aio.map[i].counter = 0;
	memset(sclib_aio.bitmap, 0xFF, sizeof(sclib_aio.bitmap));
}

void sclib_aio_destroy(sclib_aio_table_t *aio, io_context_t ctx)
{
	size_t i;
	/* Disable remote domains for now */
	for (i = SYSCALL_SYSIDS; i < SYSCALL_SYSIDS + 1; i++) {
		SCLIB_SYSID_CALL(i, io_destroy, 1, aio->map[(unsigned long) ctx].ctx[i]);
	}
}
