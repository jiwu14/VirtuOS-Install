/* io_setup
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
#include "sclib_aio.h"

int io_setup(int maxevents, io_context_t *ctxp)
{
	io_context_t ctx;
	io_context_t *ref;
	unsigned long ret;
//	syscall_udw_t dwret;
	size_t i;

	if (unlikely(*ctxp != 0))
		return -EINVAL;

	ctx = sclib_aio_add(&sclib_aio);
	SCLIB_SYS_RET((unsigned long) ctx);
	ref = sclib_aio_ref(&sclib_aio, ctx);

	for (i = 0; i < SYSCALL_SYSIDS; i++) {
#if 0
		dwret = SCLIB_REMOTE_CALL_DW(io_setup, 2, maxevents, 0);
		ret = syscall_result_lower(dwret);
		SCLIB_VAL_RET(ret, ret);
		ref[i] = (io_context_t) syscall_result_upper(dwret);
#else /* Disable remote domains for now */
		ref[i] = (io_context_t) 0;
#endif
	}

	ref[SYSCALL_SYSID_LOCAL] = 0;
	ret = SCLIB_LOCAL_CALL(io_setup, 2, maxevents, ref + SYSCALL_SYSID_LOCAL);
	SCLIB_VAL_RET(ret, ret);

	sclib_aio_add_ok(&sclib_aio, ctx);
	*ctxp = ctx;
	return 0;

error_val:
#if 0
	while (i != 0) {
		--i;
		SCLIB_REMOTE_CALL(io_destroy, 1, ref[i]);
	}
#endif
	sclib_aio_add_fail(&sclib_aio, ctx);
	return ret;
}
