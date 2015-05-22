/* vi: set sw=4 ts=4: */
/*
 * capset() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 * Copyright (C) 2012 Ruslan Nikolaev <rnikola@vt.edu>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <unistd.h>
#include <linux/capability.h>
#include <bits/sclib.h>

int capset(void *header, const void *data);
#ifdef __NR_capset
int capset(void *_header, const void *_data)
{
	cap_user_header_t mem_header[SYSCALL_SYSIDS], header = (cap_user_header_t) _header;
	cap_user_data_t mem_data;
	const cap_user_data_t data = (const cap_user_data_t) _data;
	syscall_entry_t *pos[SYSCALL_SYSIDS];
	long ret, rret;
	size_t sysid;

	/* With VFS support only */
	if (header->pid != getpid() && header->pid != 0) {
		__set_errno(EINVAL);
		return -1;
	}

	for (sysid = 0; sysid < SYSCALL_SYSIDS; sysid++) {
		mem_header[sysid] = (cap_user_header_t) sclib_memory_alloc(&sclib_data[sysid], sizeof(struct __user_cap_header_struct) + sizeof(struct __user_cap_data_struct) * 2);
		SCLIB_MEM_RET(mem_header[sysid], ret);
		mem_header[sysid]->version = header->version;
		mem_header[sysid]->pid = 0;
		mem_data = (cap_user_data_t) (mem_header[sysid] + 1);
		mem_data[0] = data[0];
		if (header->version > _LINUX_CAPABILITY_VERSION_1)
			mem_data[1] = data[1];
		pos[sysid] = SCLIB_REMOTE_CALL_ASYNC(sysid, capset, 2, sclib_mem(sysid, mem_header[sysid]), sclib_mem(sysid, mem_data));
	}

	ret = SCLIB_LOCAL_CALL(capset, 2, header, data);

error_mem:
	while (sysid != 0) {
		sysid--;
		rret = SCLIB_REMOTE_CALL_RESULT(sysid, capset, pos[sysid]);
		if (SCLIB_IS_ERR(rret))
			ret = rret;
		sclib_memory_free(&sclib_data[sysid], mem_header[sysid]);
	}
	SCLIB_ERR_RET(ret);
	return ret;
}
#endif
