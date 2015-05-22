/* Copyright (C) 2001, 2002, 2003, 2004, 2005 Free Software Foundation, Inc.
   Copyright (C) 2012 Ruslan Nikolaev <rnikola@vt.edu>
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

/* clone() is even more special than fork() as it mucks with stacks
   and invokes a function in the right context after its all over.  */

#include <features.h>
#define _ERRNO_H 1
#include <bits/errno.h>
#include <sys/syscall.h>
#include <sysdep.h>

#define CLONE_VM	0x00000100
#define CLONE_THREAD	0x00010000
#define CLONE_VFORK		0x00004000

#ifndef __CLONE_CALL
# define __CLONE_CALL(x) HIDDEN_JUMPTARGET(x)
#endif

/* The userland implementation is:
   int clone (int (*fn)(void *arg), void *child_stack, int flags, void *arg),
   the kernel entry is:
   int clone (long flags, void *child_stack).

   The parameters are passed in register and on the stack from userland:
   rdi: fn
   rsi: child_stack
   rdx:	flags
   rcx: arg
   r8d:	TID field in parent
   r9d: thread pointer
%esp+8:	TID field in child

   The kernel expects:
   rax: system call number
   rdi: flags
   rsi: child_stack
   rdx: TID field in parent
   r10: TID field in child
   r8:	thread pointer  */


.text
.global clone
.type   clone,%function
clone:
	/* Sanity check arguments.  */
	movq	$-EINVAL,%rax
	testq	%rdi,%rdi		/* no NULL function pointers */
	jz	__syscall_error
	testq	%rsi,%rsi		/* no NULL stack pointers */
	jz	__syscall_error

	andl	$~CLONE_VFORK,%edx	/* ignore this flag, treat as fork() */

	/* Insert the argument onto the new stack.  */
#ifdef CLONE_NOWRAPPER
	subq	$16,%rsi
	movq	%rcx,8(%rsi)
#else
	subq	$24,%rsi
	movq	%rcx,16(%rsi)
#endif

	/* Save the function pointer.  It will be popped off in the
	   child in the ebx frobbing below.  */
#ifdef CLONE_NOWRAPPER
	movq	%rdi,0(%rsi)

	/* Do the system call.  */
	movq	%rdx, %rdi
	movq	%r8, %rdx
	movq	%r9, %r8

	movq	8(%rsp), %r10
#else
	movq	%rdi,8(%rsi)

	pushq	%rsi
	pushq	%rdx
	pushq	%r8
	pushq	%r9

	movq	%rdx,%rdi
	call	__CLONE_CALL(__internal_sys_clone_begin)
	testq	%rax,%rax

	popq	%r8
	popq	%rdx
	popq	%rdi
	popq	%rsi
	jl	__syscall_error

	movq	8(%rsp), %r10

	/* Keep the return value from sclib_clone_begin */
	movq	%rax,0(%rsi)		/* child */
	pushq	%rax				/* parent */

	/* Do the system call.  */
#endif
	movl	$__NR_clone,%eax

	syscall

	testq	%rax,%rax
	jz	.Lthread_start

#ifndef CLONE_NOWRAPPER
	popq	%rsi

	movq	%rax,%rdi
	call	__CLONE_CALL(__internal_sys_clone_parent)
	testq	%rax,%rax
#endif
	jl	__syscall_error

.Lpseudo_end:
	ret

.Lthread_start:
	/* Clear the frame pointer.  The ABI suggests this be done, to mark
	   the outermost frame obviously.  */
	xorl	%ebp, %ebp

#ifdef RESET_PID
	testq	$CLONE_THREAD, %rdi
	jne	1f
	testq	$CLONE_VM, %rdi
	movl	$-1, %eax
	jne	2f
	movl	$__NR_getpid, %eax
	syscall
2:	movl	%eax, %fs:PID
	movl	%eax, %fs:TID
1:
#endif

#ifndef CLONE_NOWRAPPER
	popq	%rdi		/* Restore the value */
	call	__CLONE_CALL(__internal_sys_clone_child)
#endif

	/* Set up arguments for the function call.  */
	popq	%rax		/* Function to call.  */
	popq	%rdi		/* Argument.  */
	call	*%rax
	/* Call exit with return value from function call. */
	movq	%rax, %rdi
	movl	$__NR_exit, %eax
	syscall

.size clone,.-clone
weak_alias(clone, __clone)
