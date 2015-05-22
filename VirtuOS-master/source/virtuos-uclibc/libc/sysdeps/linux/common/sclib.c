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

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/param.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/eventfd.h>
#include <string.h>
#include <sched.h>
#include <stdlib.h>
#include <errno.h>
#include <dirent.h>
#include <endian.h>
#include <features.h>
#include <bits/sclib.h>

struct linux_dirent
{
	long int d_ino;
	__kernel_off_t d_off;
	unsigned short int d_reclen;
	char d_name[0];
};

static const char *sclib_paths[SYSCALL_SYSIDS] = { "/dev/syscall_network",
	"/dev/syscall_storage" };

sclib_data_t sclib_data[SYSCALL_SYSIDS] = { { .sysid = 0, .buffer = NULL }, { .sysid = 1, .buffer = NULL } };
libc_hidden_data_def(sclib_data)

sclib_miscdata_t sclib_miscdata[SYSCALL_SYSIDS] = { [ 0 ... SYSCALL_SYSIDS-1] = {.domfd = -1, .membase = 0 } };
libc_hidden_data_def(sclib_miscdata)

sclib_file_table_t sclib_file = { };
libc_hidden_data_def(sclib_file)

struct syscall_queue *sclib_rqueue = NULL;
libc_hidden_data_def(sclib_rqueue);

size_t sclib_wait_iterations = SCLIB_WAIT_ITERATIONS;
libc_hidden_data_def(sclib_wait_iterations);

#ifdef __UCLIBC_HAS_TLS__
__thread sclib_thread_data_t sclib_thread = { .efd = { -1, -1 } };
# ifdef SCLIB_MEMORY_PREALLOC
__thread sclib_memory_block_t *sclib_memptr[SYSCALL_SYSIDS] = { NULL, NULL };
# endif
#else
# error "Need TLS support for EFDS"
#endif

long sclib_fd_open(void)
{
	long sysid;

	for (sysid = 0; sysid < SYSCALL_SYSIDS; sysid++) {
		sclib_miscdata[sysid].domfd = SCLIB_LOCAL_CALL(open, 2, sclib_paths[sysid], O_RDWR);
		if (sclib_miscdata[sysid].domfd < 0)
			goto error;
	}
	return 0;

error:
	fprintf(stderr, "ERROR: Cannot open %s\n", sclib_paths[sysid]);
	while (sysid != 0) {
		--sysid;
		SCLIB_LOCAL_CALL(close, 1, sclib_miscdata[sysid].domfd);
	}
	return -EFAULT;
}

libc_hidden_def(sclib_fd_open)

void sclib_fd_close(void)
{
	long sysid;

	for (sysid = 0; sysid < SYSCALL_SYSIDS; sysid++) {
		SCLIB_LOCAL_CALL(close, 1, sclib_miscdata[sysid].domfd);
	}
}

libc_hidden_def(sclib_fd_close)

char *sclib_get_path(char *abspath, const char *path, int *sysid, size_t *sz)
{
	char *curpath, *endpath = abspath + PATH_MAX;

	if (*path == '/') { /* Absolute path */
		do {
			path++;
		} while (*path == '/');
		curpath = abspath;
	} else { /* Relative path */
		curpath = mempcpy(abspath, sclib_file.curdir, sclib_file.curdir_size - 1);
	}

	*curpath = '/';
	while (*path != '\0') {
		if (*path == '.') {
			path++;
			if (*path == '.') {
				path++;
				if (*path == '/') { /* Parent directory */
					if (curpath != abspath) {
						do {
							curpath--;
						} while (*curpath != '/');
					}
					goto next_iteration;
				} else if (*path == '\0') { /* Parent directory (end) */
					if (curpath != abspath) {
						do {
							curpath--;
						} while (*curpath != '/');
					}
					goto exit_iterations;
				}
				path -= 2;
			} else if (*path == '/') { /* Current directory */
				goto next_iteration;
			} else if (*path == '\0') { /* Current directory (end) */
				goto exit_iterations;
			} else { /* Ordinary file */
				path--;
			}
		}

		while (*path != '/') {
			if (*path == '\0')
				goto exit_iterations;
			if (++curpath == endpath)
				goto exit;
			*curpath = *path++;
		}
		if (++curpath == endpath)
			goto exit;
		*curpath = '/';

next_iteration:
		do {
			path++;
		} while (*path == '/');
	}

exit_iterations:
	if (++curpath != endpath)
		*curpath = '\0';

exit:
	if (strncmp(abspath, SCLIB_STORAGE_PREFIX, sizeof(SCLIB_STORAGE_PREFIX) - 1) == 0)
	{
		if (abspath[sizeof(SCLIB_STORAGE_PREFIX) - 1] == '\0') {
			abspath[sizeof(SCLIB_STORAGE_PREFIX) - 1] = '/';
			abspath[sizeof(SCLIB_STORAGE_PREFIX)] = '\0';
			*sysid = SYSCALL_SYSID_STORAGE;
			abspath += sizeof(SCLIB_STORAGE_PREFIX) - 1;
			curpath = abspath + 1;
			goto done;
		} else if (abspath[sizeof(SCLIB_STORAGE_PREFIX) - 1] == '/') {
			*sysid = SYSCALL_SYSID_STORAGE;
			abspath += sizeof(SCLIB_STORAGE_PREFIX) - 1;
			goto done;
		}
	}
	*sysid = SYSCALL_SYSID_LOCAL;

done:
	*sz = (size_t) (curpath + 1 - abspath);
	if (*sz == 1) {
		*sz = 2;
		abspath[0] = '.';
		abspath[1] = '\0';
	}
	return abspath;
}

libc_hidden_def(sclib_get_path)

long sclib_efds_open(bool new_process)
{
	syscall_udw_t dwret;
	long ret;
	size_t sysid;
	syscall_entry_t *pos[SYSCALL_SYSIDS];

	for (sysid = 0; sysid < SYSCALL_SYSIDS+1; sysid++)
		sclib_thread.efd[sysid] = -1;
	/* Get task ID prior to any remote calls */
	ret = SCLIB_LOCAL_CALL(gettid, 0);
	if (SCLIB_IS_ERR(ret))
		goto error;
	sclib_thread.task_id = ret;
	if (new_process) {
		/* Request is already on the stack */
		sclib_thread.seq_num = 1;
		for (sysid = 0; sysid < SYSCALL_SYSIDS; sysid++) {
			pos[sysid] = (syscall_entry_t *) sclib_data[sysid].buffer->page.entry;
			pos[sysid]->pd = THREAD_SELF;
		}
	} else {
		/* Create new remote eventfd */
		sclib_thread.seq_num = 0;
		for (sysid = 0; sysid < SYSCALL_SYSIDS; sysid++)
			pos[sysid] = SCLIB_REMOTE_CALL_ASYNC(sysid, syscall_service_init, 1, -1);
	}
	/* Initialize local FD */
	ret = SCLIB_LOCAL_CALL(eventfd2, 2, 0, EFD_SEMAPHORE);
	sclib_thread.efd[SYSCALL_SYSIDS] = ret;
	/* Wait for remote result */
	for (sysid = 0; sysid < SYSCALL_SYSIDS; sysid++) {
		dwret = SCLIB_REMOTE_CALL_RESULT_DW(sysid, syscall_service_init, pos[sysid]);
		sclib_thread.efd[sysid] = syscall_result_lower(dwret);
		ret |= sclib_thread.efd[sysid];
		if (new_process)
			sclib_miscdata[sysid].membase = syscall_result_upper(dwret);
	}

	if (likely(ret >= 0))
		return 0;

	for (sysid = 0; sysid < SYSCALL_SYSIDS; sysid++) {
		if (sclib_thread.efd[sysid] >= 0) {
			pos[sysid] = SCLIB_REMOTE_CALL_ASYNC(sysid, close, 1, sclib_thread.efd[sysid]);
			sclib_thread.efd[sysid] = -1;
		} else {
			pos[sysid] = NULL;
		}
	}
	if (sclib_thread.efd[SYSCALL_SYSIDS] >= 0) {
		SCLIB_LOCAL_CALL(close, 1, sclib_thread.efd[SYSCALL_SYSIDS]);
		sclib_thread.efd[SYSCALL_SYSIDS] = -1;
	}
	for (sysid = 0; sysid < SYSCALL_SYSIDS; sysid++) {
		if (pos[sysid])
			SCLIB_REMOTE_CALL_RESULT(sysid, close, pos[sysid]);
	}

error:
	return -EFAULT;
}

libc_hidden_def(sclib_efds_open)

void sclib_efds_close(void)
{
	size_t sysid;
	syscall_entry_t *pos[SYSCALL_SYSIDS];

	for (sysid = 0; sysid < SYSCALL_SYSIDS; sysid++) {
		if (sclib_thread.efd[sysid] >= 0) {
			pos[sysid] = SCLIB_REMOTE_CALL_ASYNC(sysid, close, 1, sclib_thread.efd[sysid]);
			sclib_thread.efd[sysid] = -1;
		} else {
			pos[sysid] = NULL;
		}
	}
	if (sclib_thread.efd[SYSCALL_SYSIDS] >= 0) {
		SCLIB_LOCAL_CALL(close, 1, sclib_thread.efd[SYSCALL_SYSIDS]);
		sclib_thread.efd[SYSCALL_SYSIDS] = -1;
	}
	for (sysid = 0; sysid < SYSCALL_SYSIDS; sysid++) {
		if (pos[sysid])
			SCLIB_REMOTE_CALL_RESULT(sysid, close, pos[sysid]);
	}
}

libc_hidden_def(sclib_efds_close)

static long sclib_fds_init(sclib_file_table_t *file)
{
	long dirents[1024 / sizeof(long)]; /* Long is used for alignment */
	struct linux_dirent *ent;
	int dir, fd, size;
	long ret, rc = -EFAULT;

	sclib_file_init(file);
	ret = SCLIB_LOCAL_CALL(getcwd, 2, file->curdir, PATH_MAX);
	if (unlikely(ret < 0))
		return rc;
	file->curdir_size = ret;
	dir = SCLIB_LOCAL_CALL(open, 3, "/proc/self/fd", O_RDONLY, 0);
	if (unlikely(dir < 0))
		return rc;
	size = SCLIB_LOCAL_CALL(getdents, 3, dir, dirents, sizeof(dirents));
	if (unlikely(size < 0))
		goto done;
	ent = (struct linux_dirent *) dirents;
	while (size > 0) {
		if (ent->d_name[0] != '.') { /* Skip current and parent dirs */
			if (sscanf(ent->d_name, "%d", &fd) != 1)
				goto done;
			if (fd != dir) /* Do not add /proc/self/fd itself */
				sclib_file_replace(file, fd, fd, SYSCALL_SYSID_LOCAL, NULL);
		}
		size -= ent->d_reclen;
		ent = (struct linux_dirent *) ((char *) ent + ent->d_reclen);
	}
	rc = 0;

done:
	SCLIB_LOCAL_CALL(close, 1, dir);

	if (!rc)
		return sclib_fd_open();

	return rc;
}

static long sclib_fds_restore(void)
{
	char path[sizeof(SYSCALL_FDTABLE_PATH) + 64];
	struct iovec iov[3];
	int fd;
	long rc = 0;

	sprintf(path, SYSCALL_FDTABLE_PATH "%u", getpid());
	fd = SCLIB_LOCAL_CALL(open, 3, path, O_RDONLY, 0);
	if (unlikely(fd < 0))
		return -EFAULT;
	iov[0].iov_base = &sclib_file;
	iov[0].iov_len = sizeof(sclib_file_table_t);
	iov[1].iov_base = sclib_miscdata;
	iov[1].iov_len = sizeof(sclib_miscdata);
	iov[2].iov_base = &sclib_thread;
	iov[2].iov_len = sizeof(sclib_thread_data_t);
	if (unlikely(SCLIB_LOCAL_CALL(readv, 3, fd, iov, 3) != sizeof(sclib_file_table_t) + sizeof(sclib_miscdata) + sizeof(sclib_thread_data_t))) {
		rc = -EFAULT;
	}
	SCLIB_LOCAL_CALL(close, 1, fd);
	SCLIB_LOCAL_CALL(unlink, 1, path);
	return rc;
}

long sclib_fds_save(void)
{
	char path[sizeof(SYSCALL_FDTABLE_PATH) + 64];
	struct iovec iov[3];
	int fd;
	long rc = 0;

	sprintf(path, SYSCALL_FDTABLE_PATH "%u", getpid());
	fd = SCLIB_LOCAL_CALL(open, 3, path, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
	if (unlikely(fd < 0)) {
		return -EFAULT;
	}
	iov[0].iov_base = &sclib_file;
	iov[0].iov_len = sizeof(sclib_file_table_t);
	iov[1].iov_base = sclib_miscdata;
	iov[1].iov_len = sizeof(sclib_miscdata);
	iov[2].iov_base = &sclib_thread;
	iov[2].iov_len = sizeof(sclib_thread_data_t);
	if (unlikely(SCLIB_LOCAL_CALL(writev, 3, fd, iov, 3) != sizeof(sclib_file_table_t) + sizeof(sclib_miscdata) + sizeof(sclib_thread_data_t))) {
		rc = -EFAULT;
	}
	SCLIB_LOCAL_CALL(close, 1, fd);
	return rc;
}

libc_hidden_def(sclib_fds_save)

long sclib_fd_mmap(void)
{
	size_t sysid;
	long ret;

	/* No error handling since process exits if sclib_fd_mmap() fails */
	for (sysid = 0; sysid < SYSCALL_SYSIDS; sysid++) {
		ret = SCLIB_LOCAL_CALL(ioctl, 3, sclib_miscdata[sysid].domfd, SYSCALL_DRIVER_IOCTL_REGISTER, 0);
		if (SCLIB_IS_ERR(ret)) {
			fprintf(stderr, "ERROR: Cannot register with %s\n", sclib_paths[sysid]);
			return -EFAULT;
		}
		sclib_data[sysid].map_pos = (unsigned long) ret - SYSCALL_PAGES;
		ret = SCLIB_LOCAL_CALL(mmap, 6, NULL, SYSCALL_TOTAL_SHARED_PAGES * PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, sclib_miscdata[sysid].domfd, 0);
		if (SCLIB_IS_ERR(ret)) {
			fprintf(stderr, "ERROR: Cannot map a syscall shared buffer\n");
			return -EFAULT;
		}
		sclib_data[sysid].buffer = (void *) ret;
	}

	return 0;
}

libc_hidden_def(sclib_fd_mmap)

void sclib_init(void)
{
	bool new_process = false;
	long ret;
	unsigned long num;
	const char *str;
	size_t sysid;

	/* Number of iterations. */
	str = getenv("SCLIB_WAIT_ITERATIONS");
	if (str != NULL) {
		errno = 0;
		num = strtol(str, NULL, 10);
		if ((num != 0 && num < ULONG_MAX) || !errno)
			sclib_wait_iterations = num;
	}
	/* Initialize file descriptors first. */
	if (sclib_fds_restore() != 0) {
		if (sclib_fds_init(&sclib_file) != 0)
			exit(1);
		new_process = true;
	}
	/* Initialize other things only when we have file descriptor table. */
	if (sclib_fd_mmap() != 0) {
		sclib_fd_close();
		exit(1);
	}
	sclib_memory_init();
	sclib_memory_prealloc_init();
	if (new_process) {
		ret = sclib_efds_open(true);
		if (SCLIB_IS_ERR(ret)) {
			sclib_fd_close();
			exit(1);
		}
	}
	for (sysid = 0; sysid < SYSCALL_SYSIDS; sysid++) {
		sclib_data[sysid].memoff = sclib_miscdata[sysid].membase -
			(long) (&sclib_data[sysid].buffer->page);
	}
	/* Close O_CLOEXEC files */
	sclib_file_exec(&sclib_file);
}

libc_hidden_def(sclib_init)

void sclib_terminate(void)
{
	sclib_fd_close();
}

libc_hidden_def(sclib_terminate)

ssize_t sclib_iovec_length(const struct iovec *iov, size_t count)
{
	size_t overflow = 0;
	size_t length = 0;

	/* Calculate total length */
	for (; count != 0; count--) {
		length += iov->iov_len;
		if (unlikely((ssize_t) length < 0))
			return -EINVAL;
		overflow |= iov->iov_len;
		iov++;
	}
	if (unlikely((ssize_t) overflow < 0))
		return -EINVAL;
	return length;
}

libc_hidden_def(sclib_iovec_length)

void *sclib_copy_from_iovec(void *to, struct sclib_iovc *from, size_t length)
{
	const struct iovec *iov = from->iovc_iov;
	size_t cur, off = from->iovc_off;

	for (; length != 0; length -= cur) {
		cur = iov->iov_len - off;
		if (cur > length) {
			to = mempcpy(to, iov->iov_base + off, length);
			off += length;
			break;
		}
		to = mempcpy(to, iov->iov_base + off, cur);
		iov++;
		off = 0;
	}
	from->iovc_iov = iov;
	from->iovc_off = off;
	return to;
}

libc_hidden_def(sclib_copy_from_iovec)

void sclib_copy_to_iovec(struct sclib_iovc *to, const void *from, size_t length)
{
	const struct iovec *iov = to->iovc_iov;
	size_t cur, off = to->iovc_off;

	for (; length != 0; length -= cur) {
		cur = iov->iov_len - off;
		if (cur > length) {
			memcpy(iov->iov_base + off, from, length);
			off += length;
			break;
		}
		memcpy(iov->iov_base + off, from, cur);
		from += cur;
		iov++;
		off = 0;
	}
	to->iovc_iov = iov;
	to->iovc_off = off;
}

libc_hidden_def(sclib_copy_to_iovec)

struct msghdr *sclib_init_msghdr(struct msghdr *to, const struct msghdr *from,
								 size_t total_iovlen, struct msghdr *rto)
{
	struct iovec *iov = (struct iovec *) (to + 1);

	to->msg_iov = (struct iovec *) (rto + 1);
	to->msg_iovlen = 1;
	iov->iov_base = to->msg_iov + 1;
	iov->iov_len = total_iovlen;
	to->msg_control = iov->iov_base + total_iovlen;
	to->msg_controllen = from->msg_controllen;
	to->msg_name = NULL;
	if (from->msg_name != NULL)
		to->msg_name = to->msg_control + to->msg_controllen;
	to->msg_namelen = from->msg_namelen;
	to->msg_flags = from->msg_flags;

	return rto;
}

libc_hidden_def(sclib_init_msghdr)

void sclib_copy_from_msghdr(struct msghdr *_to, const struct msghdr *msg, size_t total_iovlen)
{
	struct sclib_iovc iovc;
	void *to = (struct iovec *) (_to + 1) + 1;

	iovc.iovc_iov = msg->msg_iov;
	iovc.iovc_off = 0;
	to = sclib_copy_from_iovec(to, &iovc, total_iovlen);
	to = mempcpy(to, msg->msg_control, msg->msg_controllen);
	if (msg->msg_name != NULL)
		memcpy(to, msg->msg_name, msg->msg_namelen);
}

libc_hidden_def(sclib_copy_from_msghdr)

void sclib_copy_to_msghdr(struct msghdr *msg, const struct msghdr *_from,
						size_t length, size_t total_iovlen,
						size_t controllen, size_t namelen)
{
	struct sclib_iovc iovc;
	void *from = (struct iovec *) (_from + 1) + 1;

	iovc.iovc_iov = msg->msg_iov;
	iovc.iovc_off = 0;
	sclib_copy_to_iovec(&iovc, from, length);
	from += total_iovlen;
	memcpy(msg->msg_control, from, MIN(controllen, msg->msg_controllen));
	from += msg->msg_controllen;
	msg->msg_controllen = controllen;
	if (msg->msg_name != NULL)
		memcpy(msg->msg_name, from, MIN(namelen, msg->msg_namelen));
	msg->msg_namelen = namelen;
}

libc_hidden_def(sclib_copy_to_msghdr)

long sclib_copy_file(long in_dfd, __off_t *in_off, long out_dfd, __off_t *out_off, size_t len, int in_sysid, int out_sysid)
{
	size_t total = 0, count = MIN(SCLIB_MAX_BUFFER, len);
	void *in_buffer, *out_buffer;
	long ret;
	int inout_sysid;

	if (in_sysid == SYSCALL_SYSID_LOCAL) {
		in_buffer = sclib_memory_alloc(&sclib_data[out_sysid], count);
		out_buffer = in_buffer;
		inout_sysid = out_sysid;
		if (unlikely(out_buffer == NULL))
			return -ENOMEM;
	} else if (out_sysid == SYSCALL_SYSID_LOCAL) {
		in_buffer = sclib_memory_alloc(&sclib_data[in_sysid], count);
		out_buffer = in_buffer;
		inout_sysid = in_sysid;
		if (unlikely(out_buffer == NULL))
			return -ENOMEM;
	} else {
		out_buffer = sclib_memory_alloc(&sclib_data[out_sysid], count);
		if (unlikely(out_buffer == NULL))
			return -ENOMEM;
		inout_sysid = out_sysid;
		in_buffer = sclib_memory_alloc(&sclib_data[in_sysid], count);
		if (unlikely(in_buffer == NULL)) {
			total = -ENOMEM;
			goto error;
		}
	}

	if (in_off && out_off) {
		for (; len != 0; len -= count) {
			if (len < count)
				count = len;
			ret = SCLIB_SYSID_CALL_BUFFER(in_sysid, pread64, 4, in_dfd, in_buffer, count, *in_off);
			SCLIB_VAL_RET(ret, total);
			*in_off += (unsigned long) ret;
			if (in_buffer != out_buffer)
				memcpy(out_buffer, in_buffer, (unsigned long) ret);
			ret = SCLIB_SYSID_CALL_BUFFER(out_sysid, pwrite64, 4, out_dfd, out_buffer, ret, *out_off);
			SCLIB_VAL_RET(ret, total);
			*out_off += (unsigned long) ret;
			total += (unsigned long) ret;
		}
	} else if (in_off) {
		for (; len != 0; len -= count) {
			if (len < count)
				count = len;
			ret = SCLIB_SYSID_CALL_BUFFER(in_sysid, pread64, 4, in_dfd, in_buffer, count, *in_off);
			SCLIB_VAL_RET(ret, total);
			*in_off += (unsigned long) ret;
			if (in_buffer != out_buffer)
				memcpy(out_buffer, in_buffer, (unsigned long) ret);
			ret = SCLIB_SYSID_CALL_BUFFER(out_sysid, write, 3, out_dfd, out_buffer, ret);
			SCLIB_VAL_RET(ret, total);
			total += (unsigned long) ret;
		}
	} else if (out_off) {
		for (; len != 0; len -= count) {
			if (len < count)
				count = len;
			ret = SCLIB_SYSID_CALL_BUFFER(in_sysid, read, 3, in_dfd, in_buffer, count);  
			SCLIB_VAL_RET(ret, total);
			if (in_buffer != out_buffer)
				memcpy(out_buffer, in_buffer, (unsigned long) ret);
			ret = SCLIB_SYSID_CALL_BUFFER(out_sysid, pwrite64, 4, out_dfd, out_buffer, ret, *out_off);
			SCLIB_VAL_RET(ret, total);
			*out_off += (unsigned long) ret;
			total += (unsigned long) ret;
		}
	} else {
		for (; len != 0; len -= count) {
			if (len < count)
				count = len;
			ret = SCLIB_SYSID_CALL_BUFFER(in_sysid, read, 3, in_dfd, in_buffer, count);  
			SCLIB_VAL_RET(ret, total);
			if (in_buffer != out_buffer)
				memcpy(out_buffer, in_buffer, (unsigned long) ret);
			ret = SCLIB_SYSID_CALL_BUFFER(out_sysid, write, 3, out_dfd, out_buffer, ret);
			SCLIB_VAL_RET(ret, total);
			total += (unsigned long) ret;
		}
	}
error_val:
	if (in_buffer != out_buffer)
		sclib_memory_free(&sclib_data[in_sysid], in_buffer);
error:
	sclib_memory_free(&sclib_data[inout_sysid], out_buffer);
	return total;
}

libc_hidden_def(sclib_copy_file)

long sclib_copy64_file(long in_dfd, __off64_t *in_off, long out_dfd, __off64_t *out_off, size_t len, int in_sysid, int out_sysid)
{
	size_t total = 0, count = MIN(SCLIB_MAX_BUFFER, len);
	void *in_buffer, *out_buffer;
	long ret;
	int inout_sysid;

	if (in_sysid == SYSCALL_SYSID_LOCAL) {
		in_buffer = sclib_memory_alloc(&sclib_data[out_sysid], count);
		out_buffer = in_buffer;
		inout_sysid = out_sysid;
		if (unlikely(out_buffer == NULL))
			return -ENOMEM;
	} else if (out_sysid == SYSCALL_SYSID_LOCAL) {
		in_buffer = sclib_memory_alloc(&sclib_data[in_sysid], count);
		out_buffer = in_buffer;
		inout_sysid = in_sysid;
		if (unlikely(out_buffer == NULL))
			return -ENOMEM;
	} else {
		out_buffer = sclib_memory_alloc(&sclib_data[out_sysid], count);
		if (unlikely(out_buffer == NULL))
			return -ENOMEM;
		inout_sysid = out_sysid;
		in_buffer = sclib_memory_alloc(&sclib_data[in_sysid], count);
		if (unlikely(in_buffer == NULL)) {
			total = -ENOMEM;
			goto error;
		}
	}

	if (in_off && out_off) {
		for (; len != 0; len -= count) {
			if (len < count)
				len = count;
			ret = SCLIB_SYSID_CALL_BUFFER(in_sysid, pread64, 4, in_dfd, in_buffer, count, *in_off);
			SCLIB_VAL_RET(ret, total);
			*in_off += (unsigned long) ret;
			if (in_buffer != out_buffer)
				memcpy(out_buffer, in_buffer, (unsigned long) ret);
			ret = SCLIB_SYSID_CALL_BUFFER(out_sysid, pwrite64, 4, out_dfd, out_buffer, ret, *out_off);
			SCLIB_VAL_RET(ret, total);
			*out_off += (unsigned long) ret;
			total += (unsigned long) ret;
		}
	} else if (in_off) {
		for (; len != 0; len -= count) {
			if (len < count)
				count = len;
			ret = SCLIB_SYSID_CALL_BUFFER(in_sysid, pread64, 4, in_dfd, in_buffer, count, *in_off);
			SCLIB_VAL_RET(ret, total);
			*in_off += (unsigned long) ret;
			if (in_buffer != out_buffer)
				memcpy(out_buffer, in_buffer, (unsigned long) ret);
			ret = SCLIB_SYSID_CALL_BUFFER(out_sysid, write, 3, out_dfd, out_buffer, ret);
			SCLIB_VAL_RET(ret, total);
			total += (unsigned long) ret;
		}
	} else if (out_off) {
		for (; len != 0; len -= count) {
			if (len < count)
				count = len;
			ret = SCLIB_SYSID_CALL_BUFFER(in_sysid, read, 3, in_dfd, in_buffer, count);  
			SCLIB_VAL_RET(ret, total);
			if (in_buffer != out_buffer)
				memcpy(out_buffer, in_buffer, (unsigned long) ret);
			ret = SCLIB_SYSID_CALL_BUFFER(out_sysid, pwrite64, 4, out_dfd, out_buffer, ret, *out_off);
			SCLIB_VAL_RET(ret, total);
			*out_off += (unsigned long) ret;
			total += (unsigned long) ret;
		}
	} else {
		for (; len != 0; len -= count) {
			if (len < count)
				count = len;
			ret = SCLIB_SYSID_CALL_BUFFER(in_sysid, read, 3, in_dfd, in_buffer, count);  
			SCLIB_VAL_RET(ret, total);
			if (in_buffer != out_buffer)
				memcpy(out_buffer, in_buffer, (unsigned long) ret);
			ret = SCLIB_SYSID_CALL_BUFFER(out_sysid, write, 3, out_dfd, out_buffer, ret);
			SCLIB_VAL_RET(ret, total);
			total += (unsigned long) ret;
		}
	}
error_val:
	if (in_buffer != out_buffer)
		sclib_memory_free(&sclib_data[in_sysid], in_buffer);
error:
	sclib_memory_free(&sclib_data[inout_sysid], out_buffer);
	return total;
}

libc_hidden_def(sclib_copy64_file)

