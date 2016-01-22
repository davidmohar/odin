/*
    Copyright (C) 2016  David Mohar <david.mohar@shekaj.si>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#include <assert.h>
#include <errno.h>
#include <signal.h>

#include <sys/ptrace.h>
#include <sys/user.h>

#ifndef _TYPES_H_
 #include "types.h"
#endif

#ifdef __amd64__
#define eax rax
#define orig_eax orig_rax
#endif

#define offsetof(a, b) __builtin_offsetof(a, b)
#define get_reg(pid, name) __get_reg(pid, offsetof(struct user, regs.name))

#define SYSCALL_MAXARGS 6

#define RVAL_DECIMAL	000	/* decimal format */
#define RVAL_HEX	001	/* hex format */
#define RVAL_OCTAL	002	/* octal format */
#define RVAL_UDECIMAL	003	/* unsigned decimal format */

#define RVAL_FD		010	/* file descriptor */
#define RVAL_MASK	017	/* mask for these values */

#define RVAL_STR	020	/* Print `auxstr' field after return val */
#define RVAL_NONE	040	/* Print nothing */

#define TRACE_FILE	001	/* Trace file-related syscalls. */
#define TRACE_IPC	002	/* Trace IPC-related syscalls. */
#define TRACE_NETWORK	004	/* Trace network-related syscalls. */
#define TRACE_PROCESS	010	/* Trace process-related syscalls. */
#define TRACE_SIGNAL	020	/* Trace signal-related syscalls. */
#define TRACE_DESC	040	/* Trace file descriptor-related syscalls. */
#define TRACE_MEMORY	0100	/* Trace memory mapping-related syscalls. */
#define SYSCALL_NEVER_FAILS	0200	/* Syscall is always successful. */
#define STACKTRACE_INVALIDATE_CACHE 0400  /* Trigger proc/maps cache updating */
#define STACKTRACE_CAPTURE_ON_ENTER 01000 /* Capture stacktrace on "entering" stage */

#define TD TRACE_DESC
#define TF TRACE_FILE
#define TI TRACE_IPC
#define TN TRACE_NETWORK
#define TP TRACE_PROCESS
#define TS TRACE_SIGNAL
#define TM TRACE_MEMORY
#define NF SYSCALL_NEVER_FAILS
#define MA MAX_ARGS
#define SI STACKTRACE_INVALIDATE_CACHE
#define SE STACKTRACE_CAPTURE_ON_ENTER

static const struct syscall_ent sysents[] =
{
#include "syscallent.h"
};

#undef TD
#undef TF
#undef TI
#undef TN
#undef TP
#undef TS
#undef TM
#undef NF
#undef MA
#undef SI
#undef SE

long __get_reg(int, int);
long syscall_arg(int, int);
char* syscall_read_str(int, unsigned long);

const char* get_signame(int signum);
