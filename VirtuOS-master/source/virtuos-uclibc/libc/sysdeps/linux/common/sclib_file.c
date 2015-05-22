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

#include <errno.h>
#include <string.h>

#include <bits/sclib.h>

void sclib_file_init(sclib_file_table_t *file)
{
	size_t i;

	for (i = 0; i < SCLIB_FILE_TABLE_LENGTH; i++) {
		file->fds[i].counter = 0;
		file->fds[i].flags_counter = 1;
		file->fds[i].dfd = -1;
	}
	memset(file->bitmap, 0xFF, sizeof(file->bitmap));
	__sync_synchronize();
}

libc_hidden_def(sclib_file_init)

/* Does not check that fd is in the valid range */
void sclib_file_replace(sclib_file_table_t *file, long fd, long dfd, int sysid,
	sclib_fd_t *aux)
{
	if (sclib_replace_lock_fd(file, fd)) {
		sclib_file_close(file, fd); /* Close an existent file descriptor */
	} else {
		sclib_bitmap_toggle(file->bitmap, fd);
	}
	file->fds[fd].dfd = dfd;
	file->fds[fd].sysid = sysid;
	file->fds[fd].flags = 0;
	file->fds[fd].ectl_doms = 0xFF;
	if (sysid == SYSCALL_SYSID_ALL)
		memcpy(file->fds[fd].aux, aux, sizeof(file->fds[fd].aux));
	sclib_replace_unlock_fd(file, fd);
}

libc_hidden_def(sclib_file_replace)

void sclib_file_exec(sclib_file_table_t *file)
{
	long dfd;
	size_t fd;

	for (fd = 0; fd < SCLIB_FILE_TABLE_LENGTH; fd++) {
		file->fds[fd].flags_counter = 1;
		dfd = file->fds[fd].dfd;
		if (dfd >= 0) {
			if (file->fds[fd].flags & SCLIB_FD_EXEC) {
				if (file->fds[fd].sysid != SYSCALL_SYSID_LOCAL)
					sclib_file_close(file, fd);
				file->fds[fd].dfd = -1; /* Removed */
				sclib_bitmap_toggle(file->bitmap, fd);
				file->fds[fd].counter = 0;
			} else {
				file->fds[fd].counter = 3;
			}
		} else {
			file->fds[fd].counter = 0;
		}
	}
	__sync_synchronize();
}

libc_hidden_def(sclib_file_exec)

long sclib_file_close(sclib_file_table_t *file, long fd)
{
	long ret;
	syscall_entry_t *pos[SYSCALL_SYSIDS];

	if (file->fds[fd].sysid != SYSCALL_SYSID_ALL) {
		ret = SCLIB_SYSID_CALL(file->fds[fd].sysid, close, 1, file->fds[fd].dfd);
	} else {
		long i;
		for (i = 0; i < SYSCALL_SYSIDS; i++) {
			pos[i] = SCLIB_REMOTE_CALL_ASYNC(i, close, 1, file->fds[fd].aux[i]);
		}
		ret = SCLIB_LOCAL_CALL(close, 1, file->fds[fd].dfd);
		for (i = 0; i < SYSCALL_SYSIDS; i++) { /* Ignore errors for others */
			SCLIB_REMOTE_CALL_RESULT(i, close, pos[i]);
		}
	}
	return ret;
}

libc_hidden_def(sclib_file_close)

