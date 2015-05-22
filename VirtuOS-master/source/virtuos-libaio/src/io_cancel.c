/* io_cancel.c
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
#include <malloc.h>
#include "sclib_aio.h"

int io_cancel_0_4(io_context_t ctx, struct iocb *iocb, struct io_event *event)
{
	io_context_t *ref;
	long ret;
	int sysid;

	ret = sclib_aio_get(&sclib_aio, ctx);
	SCLIB_SYS_RET(ret);
	ref = sclib_aio_ref(&sclib_aio, ctx);
	sysid = IOCB_FLAG_GET_SYSID(iocb->u.c.flags);
	if (sysid != SYSCALL_SYSID_LOCAL) {
		struct io_event *net_event = sclib_memory_alloc(&sclib_data[sysid], sizeof(struct io_event));
		SCLIB_MEM_RET(net_event, ret);
		ret = SCLIB_REMOTE_CALL(sysid, io_cancel, 3, ref[sysid], sclib_mem(sysid, iocb->u.c.map), sclib_mem(sysid, net_event));
		memcpy(event, net_event, sizeof(struct io_event));
		sclib_memory_free(&sclib_data[sysid], net_event);
		if (!SCLIB_IS_ERR(ret)) {
			sclib_memory_free(&sclib_data[sysid], event->obj);
			event->obj = iocb;
		}
	} else {
		ret = SCLIB_LOCAL_CALL(io_cancel, 3, ref[SYSCALL_SYSID_LOCAL], iocb->u.c.map, event);
		if (!SCLIB_IS_ERR(ret)) {
			if (iocb->u.c.flags & IOCB_FLAG_RESFD)
				sclib_file_put(&sclib_file, iocb->u.c.resfd);
			sclib_file_put(&sclib_file, iocb->aio_fildes);
			free(event->obj);
			event->obj = iocb;
		}
	}
error_mem:
	sclib_aio_put(&sclib_aio, ctx);
	return ret;
}

DEFSYMVER(io_cancel_0_4, io_cancel, 0.4)
