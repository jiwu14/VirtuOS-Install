#ifndef _SCLIB_H
#define _SCLIB_H 1

struct syscall_entry;

extern void __sclib_schedule(int sysid, struct syscall_entry *entry);

#include "sclib_public.h"

#endif /* !_SCLIB_H */
