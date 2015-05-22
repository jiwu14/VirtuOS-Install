/* io_submit
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
#include <errno.h>
#include <libaio.h>
#include <malloc.h>
#include "sclib_aio.h"

int io_submit(io_context_t ctx, long nr, struct iocb **iocbs)
{
	struct iocb *iocb, *iocb_new, **iocbs_net, *iocbs_loc[1024];
	io_context_t *ref;
	struct sclib_iovc iovc;
	int sysid;
	size_t len;
	long resdfd, dfd, i, lret = -EINVAL, nret = -EINVAL, ret, loc = 0, net = 0;
	syscall_entry_t *pos;
	void *buf;

	if ((unsigned long) nr > 1024)
		return -EINVAL;

	ret = sclib_aio_get(&sclib_aio, ctx);
	SCLIB_SYS_RET(ret);
	ref = sclib_aio_ref(&sclib_aio, ctx);
	iocbs_net = sclib_memory_alloc(&sclib_data[SYSCALL_SYSID_STORAGE], sizeof(struct iocb *) * nr);
	SCLIB_MEM_RET(iocbs_net, ret);

	for (i = 0; i != nr; i++) {
		iocb = iocbs[i];
		dfd = sclib_file_getid(&sclib_file, iocb->aio_fildes, &sysid);
		SCLIB_VAL_RET(dfd, ret);
		resdfd = -1;
		if (iocb->u.c.flags & IOCB_FLAG_RESFD) {
			resdfd = sclib_file_get(&sclib_file, iocb->u.c.resfd, sysid);
			SCLIB_VAL2_RET(resdfd, ret);
		}
		if (sysid == SYSCALL_SYSID_STORAGE) {
			iocb_new = sclib_memory_alloc(&sclib_data[SYSCALL_SYSID_STORAGE], sizeof(struct iocb));
			if (unlikely(iocb_new == NULL))
				goto error_mem2;
			iocb_new = memcpy(iocb_new, iocb, sizeof(struct iocb));
			switch (iocb->aio_lio_opcode) {
			case IO_CMD_PREAD:
				len = iocb->u.c.nbytes;
				buf = sclib_memory_alloc(&sclib_data[SYSCALL_SYSID_STORAGE], len);
				if (unlikely(buf == NULL))
					goto error_mem2;
				iocb_new->u.c.buf = sclib_mem(SYSCALL_SYSID_STORAGE, buf);
				iocb_new->u.c.nbytes = len;
				break;
			case IO_CMD_PWRITE:
				len = iocb->u.c.nbytes;
				buf = sclib_memory_alloc(&sclib_data[SYSCALL_SYSID_STORAGE], len);
				if (unlikely(buf == NULL))
					goto error_mem2;
				iocb_new->u.c.buf = sclib_mem(SYSCALL_SYSID_STORAGE, buf);
				iocb_new->u.c.nbytes = len;
				memcpy(buf, iocb->u.c.buf, iocb->u.c.nbytes);
				break;
			case IO_CMD_PREADV:
				len = sclib_iovec_length((struct iovec *) iocb->u.c.buf,
					iocb->u.c.nbytes);
				if (SCLIB_IS_ERR(len)) {
					ret = len;
					goto error_val3;
				}
				buf = sclib_memory_alloc(&sclib_data[SYSCALL_SYSID_STORAGE], len);
				if (unlikely(buf == NULL))
					goto error_mem2;
				iocb_new->u.c.buf = sclib_mem(SYSCALL_SYSID_STORAGE, buf);
				iocb_new->u.c.nbytes = len;
				iocb_new->aio_lio_opcode = IO_CMD_PREAD;
				break;
			case IO_CMD_PWRITEV:
				len = sclib_iovec_length((struct iovec *) iocb->u.c.buf,
					iocb->u.c.nbytes);
				if (SCLIB_IS_ERR(len)) {
					ret = len;
					goto error_val3;
				}
				buf = sclib_memory_alloc(&sclib_data[SYSCALL_SYSID_STORAGE], len);
				if (unlikely(buf == NULL))
					goto error_mem2;
				iocb_new->u.c.buf = sclib_mem(SYSCALL_SYSID_STORAGE, buf);
				iocb_new->u.c.nbytes = len;
				iocb_new->aio_lio_opcode = IO_CMD_PWRITE;
				iovc.iovc_iov = (struct iovec *) iocb->u.c.buf;
				iovc.iovc_off = 0;
				sclib_copy_from_iovec(buf, &iovc, len);
				break;
			default:
				iocb_new->u.c.buf = NULL;
				break;
			}
			iocbs_net[net++] = sclib_mem(SYSCALL_SYSID_STORAGE, iocb_new);
		} else {
			iocb_new = malloc(sizeof(struct iocb));
			if (unlikely(iocb_new == NULL)) {
error_mem2:
				ret = -ENOMEM;
error_val3:
				if (iocb->u.c.flags & IOCB_FLAG_RESFD) {
					sclib_file_put(&sclib_file, iocb->u.c.resfd);
				}
error_val2:
				sclib_file_put(&sclib_file, iocb->aio_fildes);
				goto error_val;
			}
			iocb_new = memcpy(iocb_new, iocb, sizeof(struct iocb));
			iocbs_loc[loc++] = iocb_new;
		}
		if (resdfd >= 0)
			iocb->u.c.resfd = resdfd;
		IOCB_FLAG_SET_SYSID(iocb->u.c.flags, sysid);
		iocb->u.c.map = iocb_new;
		iocb_new->u.c.map = iocb;
		iocb_new->aio_fildes = dfd;
	}

	nret = 0;
	lret = 0;
	if (net != 0)
		pos = SCLIB_REMOTE_CALL_ASYNC(SYSCALL_SYSID_STORAGE, io_submit, 3, ref[SYSCALL_SYSID_STORAGE], net, sclib_mem(SYSCALL_SYSID_STORAGE, iocbs_net));
	if (loc != 0)
		lret = SCLIB_LOCAL_CALL(io_submit, 3, ref[SYSCALL_SYSID_LOCAL], loc, iocbs_loc);
	if (net != 0)
		nret = SCLIB_REMOTE_CALL_RESULT(SYSCALL_SYSID_STORAGE, io_submit, pos);

	if (SCLIB_IS_ERR(nret)) {
		ret = lret;
	} else if (SCLIB_IS_ERR(lret)) {
		ret = nret;
	} else {
		ret = lret + nret;
	}

	if (SCLIB_IS_ERR(ret)) {
error_val:
		while (i != 0) {
			iocb = iocbs[--i];
			if (iocb->u.c.flags & IOCB_FLAG_RESFD)
				sclib_file_put(&sclib_file, iocb->u.c.resfd);
			sclib_file_put(&sclib_file, iocb->aio_fildes);
		}
		if (SCLIB_IS_ERR(lret)) { /* Deallocate in case of errors */
			while (loc != 0) {
				iocb = iocbs_loc[--loc];
				free(iocb);
			}
		}
		if (SCLIB_IS_ERR(nret)) {
			while (net != 0) {
				iocb = sclib_usermem(SYSCALL_SYSID_STORAGE, iocbs_net[--net]);
				if (iocb->u.c.buf != NULL)
					sclib_memory_free(&sclib_data[SYSCALL_SYSID_STORAGE], sclib_usermem(SYSCALL_SYSID_STORAGE, iocb->u.c.buf));
				sclib_memory_free(&sclib_data[SYSCALL_SYSID_STORAGE], iocb);
			}
		}
	}
	sclib_memory_free(&sclib_data[SYSCALL_SYSID_STORAGE], iocbs_net);
error_mem:
	sclib_aio_put(&sclib_aio, ctx);
	return ret;
}

