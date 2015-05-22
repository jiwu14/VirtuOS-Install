#include <tcb-offsets.h>
#include <sysdep.h>
#define RESET_PID
#define __CLONE_CALL(x) JUMPTARGET(x)
#define CLONE_NOWRAPPER
#include <libc/sysdeps/linux/x86_64/clone.S>
