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

#include <memory.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <assert.h>

#include <bits/sclib.h>
#include <bits/uClibc_mutex.h>

#define memory_block_entry(elem,member) ((sclib_memory_block_t *) ((char *) &elem->pred - offsetof(sclib_memory_list_t, pred) - offsetof(sclib_memory_block_t, member)))

__UCLIBC_MUTEX_STATIC(memory_lock, __SCLIB_MUTEX_RECURSIVE);

static inline void memory_do_expand(long domfd, long num)
{
	if (SCLIB_LOCAL_CALL(ioctl, 3, domfd,
		SYSCALL_DRIVER_IOCTL_EXPAND_BUFFER, num) != num) {
		fprintf(stderr, "ERROR: Cannot expand the data buffer\n");
		exit(1);
	}
}

static inline uint32_t round_up_power2(uint32_t num)
{
	num--;
	num |= num >> 1;
	num |= num >> 2;
	num |= num >> 4;
	num |= num >> 8;
	num |= num >> 16;
	num++;
	return num;
}

static sclib_memory_block_t * memory_expand(sclib_data_t * data, size_t size)
{
	sclib_memory_block_t *node;
	sclib_memory_binfo_t *foot;
	sclib_memory_list_t *succ;
	uint32_t new_pos, old_pos, num;

	node = (sclib_memory_block_t *) data->map_end;
	old_pos = data->map_pos;
	new_pos = round_up_power2(old_pos + (size + PAGE_SIZE - 1) / PAGE_SIZE);
	if (new_pos > SYSCALL_DATA_SHARED_PAGES) {
		if (old_pos == SYSCALL_DATA_SHARED_PAGES)
			return NULL;
		new_pos = SYSCALL_DATA_SHARED_PAGES;
	}
	num = new_pos - old_pos;
	memory_do_expand(sclib_miscdata[data->sysid].domfd, num);
	data->map_pos = new_pos;
	size = (size_t) num * PAGE_SIZE;
	data->map_end += size;
	/* Coalesce the upper part */
	foot = (sclib_memory_binfo_t *) node - 1;
	if ((char *) foot > data->map_start
		&& foot->magic == SCLIB_MEMORY_MAGIC_FREE) {
		node = (sclib_memory_block_t *) ((char *) node - foot->size);
		size += foot->size;
	} else {
		succ = data->memory.succ;
		succ->pred = &node->list;
		data->memory.succ = &node->list;
		node->list.succ = succ;
		node->list.pred = &data->memory;
		node->block.magic = SCLIB_MEMORY_MAGIC_FREE;
	}
	node->block.size = size;
	foot = (sclib_memory_binfo_t *) ((char *) node + size) - 1;
	*foot = node->block;
	return node;
}

static sclib_memory_block_t *memory_find(sclib_data_t * data, size_t size)
{
	sclib_memory_list_t *start = &data->memory;
	sclib_memory_list_t *cur = data->memory.succ;
	while (cur != start) {
		sclib_memory_block_t *ent = memory_block_entry(cur, list);
		if (ent->block.size >= size)
			return ent;
		cur = cur->succ;
	}
	return NULL;
}

static sclib_memory_block_t *memory_place(sclib_data_t * data,
										  sclib_memory_block_t * node,
										  size_t size)
{
	sclib_memory_list_t * pred, * succ;
	sclib_memory_block_t * alloc;
	sclib_memory_binfo_t * foot;
	size_t remsize;

	remsize = node->block.size - size;
	if (remsize > sizeof(sclib_memory_block_t) + sizeof(sclib_memory_binfo_t)) {
		/* Reduce the size of the free block */
		alloc = (sclib_memory_block_t *) ((char *) node + remsize);
		node->block.size = remsize;
		foot = (sclib_memory_binfo_t *) alloc - 1;
		*foot = node->block;
		alloc->block.size = size;
	} else {
		size = node->block.size;
		/* Exclude from the list */
		pred = node->list.pred;
		succ = node->list.succ;
		pred->succ = succ;
		succ->pred = pred;
		alloc = node;
	}

	alloc->block.magic = SCLIB_MEMORY_MAGIC_ALLOC;
	foot = (sclib_memory_binfo_t *) ((char *) alloc + size) - 1;
	*foot = alloc->block;
	return alloc;
}

void sclib_memory_init(void)
{
	sclib_data_t *data;

	for (data = &sclib_data[0]; data != &sclib_data[SYSCALL_SYSIDS]; data++) {
		sclib_memory_block_t *node;
		sclib_memory_binfo_t *foot;
		size_t size = data->map_pos * PAGE_SIZE;

		data->map_start = (char *) data->buffer->data;
		data->map_end = (char *) data->map_start + size;
		if (size) { /* At least 1 page, already aligned */
			node = (sclib_memory_block_t *) data->map_start;
			node->list.succ = &data->memory;
			node->list.pred = &data->memory;
			node->block.magic = SCLIB_MEMORY_MAGIC_FREE;
			node->block.size = size;
			foot = (sclib_memory_binfo_t *) data->map_end - 1;
			*foot = node->block;
			data->memory.pred = &node->list;
			data->memory.succ = &node->list;
		} else {
			data->memory.pred = &data->memory;
			data->memory.succ = &data->memory;
		}
	}
}

libc_hidden_def(sclib_memory_init)

#ifndef SCLIB_MEMORY_PREALLOC
inline
#endif
static void sclib_do_memory_free(sclib_data_t *data, sclib_memory_block_t *node)
{
	sclib_memory_block_t *next;
	sclib_memory_list_t *pred, *succ;
	sclib_memory_binfo_t *foot;
	size_t size;
	int rc = 0;

	__UCLIBC_MUTEX_LOCK(memory_lock);
	if (node->block.magic != SCLIB_MEMORY_MAGIC_ALLOC) {
		rc = 1;
		goto error;
	}
	size = node->block.size;
	node->block.magic = SCLIB_MEMORY_MAGIC_FREE;
	foot = (sclib_memory_binfo_t *) ((char *) node + size) - 1;
	foot->magic = SCLIB_MEMORY_MAGIC_FREE;
	/* Coalesce the upper part */
	foot = (sclib_memory_binfo_t *) node - 1;
	if ((char *) foot > data->map_start
		&& foot->magic == SCLIB_MEMORY_MAGIC_FREE) {
		node = (sclib_memory_block_t *) ((char *) node - foot->size);
		/* Exlude the element from the list */
		pred = node->list.pred;
		succ = node->list.succ;
		pred->succ = succ;
		succ->pred = pred;
		/* Coalescing */
		size += foot->size;
		node->block.size = size;
		foot = (sclib_memory_binfo_t *) ((char *) node + size) - 1;
		foot->size = size;
	}
	/* Coalesce the lower part */
	next = (sclib_memory_block_t *) ((char *) node + size);
	if ((char *) next < data->map_end
		&& next->block.magic == SCLIB_MEMORY_MAGIC_FREE) {
		/* Exclude the element from the list */
		pred = next->list.pred;
		succ = next->list.succ;
		pred->succ = succ;
		succ->pred = pred;
		/* Coalescing */
		size += next->block.size;
		node->block.size = size;
		foot = (sclib_memory_binfo_t *) ((char *) node + size) - 1;
		foot->size = size;
	}
	/* Add to the list of free blocks */
	succ = data->memory.succ;
	node->list.pred = &data->memory;
	node->list.succ = succ;
	succ->pred = &node->list;
	data->memory.succ = &node->list;

error:
	__UCLIBC_MUTEX_UNLOCK(memory_lock);
	if (rc) {
		fprintf(stderr, "ERROR: Invalid memory reference\n");
		exit(1);
	}
}

void *sclib_memory_alloc(sclib_data_t *data, size_t size)
{
	sclib_memory_block_t *node;

	if (size > SYSCALL_DATA_SHARED_PAGES * PAGE_SIZE -
	    2 * sizeof(sclib_memory_binfo_t))
		return NULL;

	size = (size + SCLIB_MEMORY_ALIGN - 1) & ~(SCLIB_MEMORY_ALIGN - 1);
	size += 2 * sizeof(sclib_memory_binfo_t);

#ifdef SCLIB_MEMORY_PREALLOC
	node = __sync_lock_test_and_set(&sclib_memptr[data->sysid], NULL); 

	if (node != NULL) {
		if (node->block.size >= size)
			goto done;
		sclib_do_memory_free(data, node);
	}
#endif

	while (1) {
		__UCLIBC_MUTEX_LOCK(memory_lock);
		node = memory_find(data, size);
		/* Expand the buffer if necessary */
		if (!node) {
			node = memory_expand(data, size);
			if (!node)
				goto again;
		}
		node = memory_place(data, node, size);
again:
		__UCLIBC_MUTEX_UNLOCK(memory_lock);
		if (node)
			break;
		sched_yield();
	}

#ifdef SCLIB_MEMORY_PREALLOC
done:
#endif
	return (char *) node + sizeof(sclib_memory_binfo_t);
}

libc_hidden_def(sclib_memory_alloc)

void sclib_memory_free(sclib_data_t *data, void *addr)
{
	sclib_memory_block_t *node;
	node = (sclib_memory_block_t *) ((char *) addr - sizeof(sclib_memory_binfo_t));
#ifdef SCLIB_MEMORY_PREALLOC
	node = __sync_lock_test_and_set(&sclib_memptr[data->sysid], node); 
	if (node != NULL)
		sclib_do_memory_free(data, node);
#else
	sclib_do_memory_free(data, node);
#endif
}

libc_hidden_def(sclib_memory_free)

#ifdef SCLIB_MEMORY_PREALLOC
void sclib_memory_prealloc_exit(void)
{
	size_t sysid;

	for (sysid = 0; sysid < SYSCALL_SYSIDS; sysid++) {
		sclib_memory_block_t *node;
		node = __sync_lock_test_and_set(&sclib_memptr[sysid], NULL); 
		if (node != NULL)
			sclib_do_memory_free(&sclib_data[sysid], node);
	}
}

libc_hidden_def(sclib_memory_prealloc_exit)
#endif

