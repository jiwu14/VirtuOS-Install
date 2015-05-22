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

#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <stdio.h>
#include <bits/sclib.h>
#include <bits/sclib_syscalls.h>

long __internal_sys_read(int fd, void *buf, size_t count)
{
	int sysid;
	size_t size;
	long dfd = sclib_file_getid(&sclib_file, fd, &sysid);

	SCLIB_SYS_RET(dfd);
	if (sysid != SYSCALL_SYSID_LOCAL) {
		size_t ret, chunk = MIN(count, SCLIB_MAX_BUFFER);
		void *rbuf, *mem = sclib_memory_alloc(&sclib_data[sysid], chunk);

		SCLIB_MEM_RET(mem, size);
		size = 0;
		rbuf = sclib_mem(sysid, mem);

		for (; count > chunk; count -= chunk) {
			ret = SCLIB_REMOTE_CALL(sysid, read, 3, dfd, rbuf, chunk);
			SCLIB_VAL_RET(ret, size);
			size += ret;
			buf = mempcpy(buf, mem, ret);
			if (unlikely(ret < chunk))
				goto error_val;
		}
		ret = SCLIB_REMOTE_CALL(sysid, read, 3, dfd, rbuf, count);
		SCLIB_VAL_RET(ret, size);
		size += ret;
		memcpy(buf, mem, ret);

error_val:
		sclib_memory_free(&sclib_data[sysid], mem);
	} else {
		size = SCLIB_LOCAL_CALL(read, 3, dfd, buf, count);
	}

error_mem:
	sclib_file_put(&sclib_file, fd);
	return size;
}

libc_hidden_def(__internal_sys_read)

long __internal_sys_write(int fd, const void *buf, size_t count)
{
	int sysid;
	size_t size;
	long dfd = sclib_file_getid(&sclib_file, fd, &sysid);

	SCLIB_SYS_RET(dfd);
	if (sysid != SYSCALL_SYSID_LOCAL) {
		size_t ret, chunk = MIN(count, SCLIB_MAX_BUFFER);
		void *rbuf, *mem = sclib_memory_alloc(&sclib_data[sysid], chunk);

		SCLIB_MEM_RET(mem, size);
		size = 0;
		rbuf = sclib_mem(sysid, mem);

		for (; count > chunk; count -= chunk) {
			memcpy(mem, buf, chunk);
			buf += chunk;
			ret = SCLIB_REMOTE_CALL(sysid, write, 3, dfd, rbuf, chunk);
			SCLIB_VAL_RET(ret, size);
			size += ret;
			if (unlikely(ret < chunk))
				goto error_val;
		}
		memcpy(mem, buf, count);
		ret = SCLIB_REMOTE_CALL(sysid, write, 3, dfd, rbuf, count);
		SCLIB_VAL_RET(ret, size);
		size += ret;

error_val:
		sclib_memory_free(&sclib_data[sysid], mem);
	} else {
		size = SCLIB_LOCAL_CALL(write, 3, dfd, buf, count);
	}

error_mem:
	sclib_file_put(&sclib_file, fd);
	return size;
}

libc_hidden_def(__internal_sys_write)

long __internal_sys_open(const char * file, int flags, int mode)
{
	long dfd, fd;
	uint8_t dfd_flags = 0;
	char abspath[PATH_MAX + 8], *dpath;
	int sysid;
	void *rbuf;
	size_t sz;

	dpath = sclib_get_path(abspath, file, &sysid, &sz);
	/* Translate /proc/.../{fd,fdinfo} paths */
	if (unlikely(strncmp(dpath, "/proc/", 6) == 0)) {
		char *fdstr;
		int tran_fd;
		long tran_dfd;

		/* Have both since they may be terminated by '/' */
		fdstr = dpath + 6;
		if (strncmp(fdstr, "self/", 5) != 0) {
			char pid_buf[16];
			int pid_len = sprintf(pid_buf, "%u/", getpid());
			if (strncmp(fdstr, pid_buf, pid_len) != 0)
				goto skip;
			fdstr += pid_len;
		} else {
			fdstr += 5;
		}
		if (strncmp(fdstr, "fd", 2) != 0)
			goto skip;
		fdstr += 2;
		if (strncmp(fdstr, "info", 4) == 0)
			fdstr += 4;
		if (*fdstr == '\0') {
			dfd_flags |= SCLIB_FD_TRAN;
		} else if (*fdstr == '/') {
			fdstr++;
			if (*fdstr == '\0') {
				dfd_flags |= SCLIB_FD_TRAN;
			} else {
				if (fdstr[0] != '.') {
					/* Opening a file rather than directory */
					if (sscanf(fdstr, "%d", &tran_fd) != 1 ||
						(tran_dfd = sclib_file_get(&sclib_file,
							tran_fd, sysid)) < 0) {
						return -EINVAL;
					}
					sclib_file_put(&sclib_file, tran_fd);
					sprintf(fdstr, "%d", (int) tran_dfd);
				}
			}
		}
	}

skip:
	fd = sclib_file_add(&sclib_file, 0);
	if (SCLIB_IS_ERR(fd))
		goto error;

	if (sysid != SYSCALL_SYSID_LOCAL) {
		rbuf = sclib_memory_alloc(&sclib_data[sysid], sz);
		SCLIB_MEM_RET(rbuf, dfd);
		memcpy(rbuf, dpath, sz);
		dfd = SCLIB_REMOTE_CALL(sysid, open, 3, sclib_mem(sysid, rbuf), flags, mode);
		sclib_memory_free(&sclib_data[sysid], rbuf);
	} else {
		dfd = SCLIB_LOCAL_CALL(open, 3, dpath, flags, mode);
	}

error_mem:
	if (SCLIB_IS_ERR(dfd)) {
		sclib_file_add_fail(&sclib_file, fd);
		fd = dfd;
	} else {
		if (flags & O_CLOEXEC)
			dfd_flags |= SCLIB_FD_EXEC;
		sclib_file_add_ok(&sclib_file, fd, dfd, sysid, dfd_flags, 0);
	}

error:
	return fd;
}

libc_hidden_def(__internal_sys_open)

long __internal_sys_close(int fd)
{
	int sysid;
	long dfd = sclib_file_getid(&sclib_file, fd, &sysid);

	SCLIB_SYS_RET(dfd);
	sclib_file_release(&sclib_file, fd);
	return 0;
}

libc_hidden_def(__internal_sys_close)

long __internal_sys_clone_begin(long flags)
{
	int cloneVM = (flags & CLONE_VM) != 0;
	int cloneFD = (flags & CLONE_FILES) != 0;
	long dfd;

	if (cloneVM != cloneFD) /* Not supported */
		return -EFAULT;
	if (cloneVM)
		return SCLIB_CLONE_THREAD;
	dfd = SCLIB_LOCAL_CALL(eventfd, 2, 0, 0);
	return dfd;
}

libc_hidden_def(__internal_sys_clone_begin)

void __internal_sys_clone_child(long dfd)
{
	long ret = 0;
	uint64_t val;
	size_t sysid;

	if (dfd != SCLIB_CLONE_THREAD) {
		SCLIB_LOCAL_CALL(munmap, 2, sclib_rqueue, SYSCALL_QUEUE_PAGES * PAGE_SIZE);
		sclib_init_minimal();
		sclib_fd_close();
		ret = sclib_fd_open();
		if (likely(ret >= 0)) {
			ret = sclib_fd_mmap();
			if (likely(ret >= 0)) {
				sclib_memory_init();
				sclib_memory_prealloc_init();
				/* The following statement will also block the task
				 until it is truly added, as we need to get response from
				 a remote domain. */
				ret = sclib_efds_open(true);
				if (ret == 0) {
					for (sysid = 0; sysid < SYSCALL_SYSIDS; sysid++)
						sclib_data[sysid].memoff = sclib_miscdata[sysid].membase - (long) (&sclib_data[sysid].buffer->page);
				}
			}
		}
		val = -ret + 1; /* Put an error code */
		SCLIB_LOCAL_CALL(write, 3, dfd, &val, sizeof(val));
		SCLIB_LOCAL_CALL(close, 1, dfd);
		if (unlikely(ret != 0)) { /* Error code is sent to the parent */
			/* Sclib file descriptor will be closed if it is open anyway */
			exit(1);
		}
	} else {
		__internal_sys_clone_thread();
	}
}

libc_hidden_def(__internal_sys_clone_child)

long __internal_sys_clone_parent(long ret, long dfd)
{
	uint64_t val;
	long err;

	if (dfd != SCLIB_CLONE_THREAD) {
		if (!SCLIB_IS_ERR(ret)) {
			SCLIB_LOCAL_CALL(read, 3, dfd, &val, sizeof(val));
			err = -(int64_t) (val - 1);
			if (unlikely(err != 0))
				ret = err;
		}
		SCLIB_LOCAL_CALL(close, 1, dfd);
	}
	return ret;
}

libc_hidden_def(__internal_sys_clone_parent)

long __internal_sys_fork(void)
{
	long ret, param;

	param = __internal_sys_clone_begin(0);
	if (SCLIB_IS_ERR(param))
		return param;

	ret = SCLIB_LOCAL_CALL(clone, 4,
			CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID | SIGCHLD, 0,
			NULL, &KTHREAD_SELF->ktid);

	if (ret == 0) { /* Child */
		__internal_sys_clone_child(param);
	} else { /* Parent */
		ret = __internal_sys_clone_parent(ret, param);
	}
	return ret;
}

libc_hidden_def(__internal_sys_fork)

