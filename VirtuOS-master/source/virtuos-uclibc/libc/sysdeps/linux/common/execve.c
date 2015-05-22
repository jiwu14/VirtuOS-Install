/* vi: set sw=4 ts=4: */
/*
 * execve() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 * Copyright (C) 2012 Ruslan Nikolaev <rnikola@vt.edu>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
#include <sys/param.h>

#include <bits/sclib.h>

int execve(const char *filename, char *const *argv, char *const *envp)
{
	static const char *lib_path = "LD_LIBRARY_PATH=" SCLIB_LIB_PATH;
	char **envcur, **nenvp;
	size_t envlen;
	long ret;

	for (envcur = (char **) envp; *envcur != NULL; envcur++) {
		if (strstr(*envcur, "LD_LIBRARY_PATH=") != NULL) {
			nenvp = (char **) envp;
			goto skip;
		}
	}

	envlen = (size_t) ((char *) envcur - (char *) envp);
	nenvp = malloc(envlen + 2);
	SCLIB_MEM_RET(nenvp, ret);
	envcur = mempcpy(nenvp, envp, envlen);
	envcur[0] = (char *) lib_path;
	envcur[1] = NULL;

skip:
	ret = sclib_fds_save();
	SCLIB_VAL_RET(ret, ret);
	ret = SCLIB_LOCAL_CALL(execve, 3, filename, argv, nenvp);
	SCLIB_VAL_RET(ret, ret);
	return ret;

error_val:
	if (envp != nenvp)
		free(nenvp);
error_mem:
	__set_errno(-ret);
	return -1;
}

libc_hidden_def(execve)
