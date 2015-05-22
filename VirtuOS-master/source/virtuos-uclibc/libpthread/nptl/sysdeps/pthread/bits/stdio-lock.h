/* Thread package specific definitions of stream lock type.  NPTL version.
   Copyright (C) 2000, 2001, 2002, 2003, 2007 Free Software Foundation, Inc.
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

#ifndef _BITS_STDIO_LOCK_H
#define _BITS_STDIO_LOCK_H 1

#include <bits/libc-lock.h>
#include <lowlevellock.h>
#include <schedule_defsP.h>


/* The locking here is very inexpensive, even for inlining.  */
#define _IO_lock_inexpensive	1

typedef struct { struct __sclib_mutex_auto lock; int cnt; void *owner; } _IO_lock_t;

#define _IO_lock_initializer { LLL_LOCK_INITIALIZER, 0, NULL }

#define _IO_lock_init(_name)   \
  do {  \
     (_name).cnt = 0; \
     (_name).owner = NULL; \
     __sclib_mutex_auto_init (&(_name).lock, 0); \
  } while (0)

#define _IO_lock_fini(_name) \
  __sclib_mutex_auto_destroy (&(_name).lock)

#define _IO_lock_lock(_name) \
  do {									      \
    void *__meself = THREAD_SELF;						      \
    if ((_name).owner != __meself)					      \
      {									      \
	__sclib_mutex_auto_lock (&(_name).lock);				      \
        (_name).owner = __meself;						      \
      }									      \
    ++(_name).cnt;							      \
  } while (0)

#define _IO_lock_trylock(_name) \
  ({									      \
    int __result = 0;							      \
    void *__meself = THREAD_SELF;						      \
    if ((_name).owner != __meself)					      \
      {									      \
        if (__sclib_mutex_auto_trylock (&(_name).lock) == 0)		\
          {								      \
            (_name).owner = __meself;					      \
            (_name).cnt = 1;						      \
          }								      \
        else								      \
          __result = EBUSY;						      \
      }									      \
    else								      \
      ++(_name).cnt;							      \
    __result;								      \
  })

#define _IO_lock_unlock(_name) \
  do {									      \
    if (--(_name).cnt == 0)						      \
      {									      \
        (_name).owner = NULL;						      \
	__sclib_mutex_auto_unlock (&(_name).lock);				      \
      }									      \
  } while (0)



#define _IO_cleanup_region_start(_fct, _fp) \
  __libc_cleanup_region_start (((_fp)->_flags & _IO_USER_LOCK) == 0, _fct, _fp)
#define _IO_cleanup_region_start_noarg(_fct) \
  __libc_cleanup_region_start (1, _fct, NULL)
#define _IO_cleanup_region_end(_doit) \
  __libc_cleanup_region_end (_doit)

#if defined _LIBC && !defined NOT_IN_libc

# ifdef __EXCEPTIONS
#  define _IO_acquire_lock(_fp) \
  do {									      \
    _IO_FILE *_IO_acquire_lock_file					      \
	__attribute__((cleanup (_IO_acquire_lock_fct)))			      \
	= (_fp);							      \
    _IO_flockfile (_IO_acquire_lock_file);
#  define _IO_acquire_lock_clear_flags2(_fp) \
  do {									      \
    _IO_FILE *_IO_acquire_lock_file					      \
	__attribute__((cleanup (_IO_acquire_lock_clear_flags2_fct)))	      \
	= (_fp);							      \
    _IO_flockfile (_IO_acquire_lock_file);
# else
#  define _IO_acquire_lock(_fp) _IO_acquire_lock_needs_exceptions_enabled
#  define _IO_acquire_lock_clear_flags2(_fp) _IO_acquire_lock (_fp)
# endif
# define _IO_release_lock(_fp) ; } while (0)

#endif

#endif /* bits/stdio-lock.h */
