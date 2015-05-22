/* io_getevents.c
   libaio Linux async I/O interface
   Copyright 2002 Red Hat, Inc.
   Copyright 2012 Ruslan Nikolaev <rnikola@vt.edu>

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 */
#include <libaio.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h>
#include <malloc.h>
#include "sclib_aio.h"

#define AIO_RING_MAGIC                  0xa10a10a1

/* Ben will hate me for this */
struct aio_ring {
	unsigned        id;     /* kernel internal index number */
	unsigned        nr;     /* number of io_events */
	unsigned        head;
	unsigned        tail;
 
	unsigned        magic;
	unsigned        compat_features;
	unsigned        incompat_features;
	unsigned        header_length;  /* size of aio_ring */
};

static inline int local_io_getevents(io_context_t ctx, long min_nr, long nr, struct io_event * events, struct timespec * timeout)
{
	struct aio_ring *ring;
	ring = (struct aio_ring*)ctx;
	if (ring==NULL || ring->magic != AIO_RING_MAGIC)
		goto do_syscall;
	if (timeout!=NULL && timeout->tv_sec == 0 && timeout->tv_nsec == 0) {
		if (ring->head == ring->tail)
			return 0;
	}
	
do_syscall:	
	return SCLIB_LOCAL_CALL(io_getevents, 5, ctx, min_nr, nr, events, timeout);
}

int io_getevents_0_4(io_context_t ctx, long min_nr, long nr, struct io_event *events, struct timespec *timeout)
{
	struct iocb *iocb, *iocb_map;
	io_context_t *ref;
	long ret, i;

	ret = sclib_aio_get(&sclib_aio, ctx);
	SCLIB_SYS_RET(ret);
	ref = sclib_aio_ref(&sclib_aio, ctx);
	ret = local_io_getevents(ref[SYSCALL_SYSID_LOCAL], min_nr, nr, events, timeout);
	if (!SCLIB_IS_ERR(ret)) {
		for (i = 0; i < ret; i++) {
			iocb_map = events[i].obj;
			iocb = iocb_map->u.c.map;
			events[i].obj = iocb;
			if (iocb->u.c.flags & IOCB_FLAG_RESFD)
				sclib_file_put(&sclib_file, iocb->u.c.resfd);
			sclib_file_put(&sclib_file, iocb->aio_fildes);
			free(iocb_map);
		}
	}
	sclib_aio_put(&sclib_aio, ctx);
	return ret;
}

DEFSYMVER(io_getevents_0_4, io_getevents, 0.4)
