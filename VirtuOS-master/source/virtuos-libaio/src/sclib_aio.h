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

#ifndef _SCLIB_AIO_H
#define _SCLIB_AIO_H 1

#include "libaio.h"

#define libc_hidden_proto(x)

#include "syscall.h"

#ifndef __cplusplus
# define true	1
# define false	0
typedef unsigned char bool;
#endif

#include "sclib.h"

#define IOCB_FLAG_RESFD				(1 << 0)
#define IOCB_FLAG_SET_SYSID(x,s)	((x) |= ((s) << 1))
#define IOCB_FLAG_GET_SYSID(x)		(((x) >> 1) & 0xF)

#define SCLIB_AIO_TABLE_LENGTH	1024

#define SCLIB_AIO_IS_LOCAL(ent)	\
	if ((unsigned long) (-ent->c.u.lfd) < 4096)

typedef struct sclib_aio_entry_s {
	io_context_t	ctx[SYSCALL_SYSIDS+1];
	unsigned long	counter;
} sclib_aio_entry_t;

typedef struct sclib_aio_table_s {
	sclib_aio_entry_t	map[SCLIB_AIO_TABLE_LENGTH];
	unsigned long bitmap[SCLIB_AIO_TABLE_LENGTH / (sizeof(long) * 8)];
} sclib_aio_table_t;

sclib_aio_table_t sclib_aio;

void sclib_aio_destroy(sclib_aio_table_t *aio, io_context_t ctx);

static inline bool sclib_incref_aio(sclib_aio_table_t *aio, io_context_t ctx)
{
	unsigned long val;

	/* Increment if context is in ready state */
	do {
		val = aio->map[(unsigned long) ctx].counter;
		if (val <= 2)
			return false;
	} while (!__sync_bool_compare_and_swap(&aio->map[(unsigned long) ctx].counter, val, val + 1));
	return true;
}

static inline void sclib_putref_aio(sclib_aio_table_t *aio, io_context_t ctx, unsigned long step)
{
	if (__sync_sub_and_fetch(&aio->map[(unsigned long) ctx].counter, step) == 2) {
		sclib_aio_destroy(aio, ctx);
		sclib_bitmap_toggle(aio->bitmap, (unsigned long) ctx);
		__sync_fetch_and_sub(&aio->map[(unsigned long) ctx].counter, 2);
	}
}

static inline io_context_t sclib_aio_add(sclib_aio_table_t *aio)
{
	long ctx;
	SCLIB_LOCK_CHECK_INIT

	do {
		SCLIB_LOCK_CHECK_STEP
		/* Optimistic search */
		ctx = sclib_bitmap_find(aio->bitmap, sizeof(aio->bitmap), 0);
		if (unlikely(ctx < 0))
			return (io_context_t) ctx;
	} while (!__sync_bool_compare_and_swap(&aio->map[ctx].counter, 0, 1));
	sclib_bitmap_toggle(aio->bitmap, ctx);
	return (io_context_t) ctx;
}

static inline void sclib_aio_add_fail(sclib_aio_table_t *aio, io_context_t ctx)
{
	sclib_bitmap_toggle(aio->bitmap, (unsigned long) ctx);
	__sync_fetch_and_sub(&aio->map[(unsigned long) ctx].counter, 1);
}

static inline void sclib_aio_add_ok(sclib_aio_table_t *aio, io_context_t ctx)
{
	__sync_fetch_and_add(&aio->map[(unsigned long) ctx].counter, 2);
}

static inline long sclib_aio_get(sclib_aio_table_t *aio, io_context_t ctx)
{
	if (unlikely((unsigned long) ctx >= SCLIB_AIO_TABLE_LENGTH
			|| !sclib_incref_aio(aio, ctx)))
		return -EINVAL;
	return 0;
}

static inline io_context_t *sclib_aio_ref(sclib_aio_table_t *aio, io_context_t ctx)
{
	return aio->map[(unsigned long) ctx].ctx;
}

static inline void sclib_aio_put(sclib_aio_table_t *aio, io_context_t ctx)
{
	sclib_putref_aio(aio, ctx, 1);
}

static inline void sclib_aio_release(sclib_aio_table_t *aio, io_context_t ctx)
{
	sclib_putref_aio(aio, ctx, 2);
}

#endif /* !_SCLIB_AIO_H */
