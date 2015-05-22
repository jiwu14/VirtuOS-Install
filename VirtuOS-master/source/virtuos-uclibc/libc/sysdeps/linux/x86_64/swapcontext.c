#include <sysdep.h>
#include <stdarg.h>
#include <stdint.h>
#include <ucontext.h>

static int
__swapcontext (ucontext_t *oucp, const ucontext_t *ucp)
{
  return -((long) swapcontextp (oucp, ucp) == -1L);
}

weak_alias (__swapcontext, swapcontext)
