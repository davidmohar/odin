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
#ifndef __SIGSTAT_H__
#define __SIGSTAT_H__

#include <stdio.h>
#include <signal.h>

#include "types.h"

#define SIG_SENT        0
#define SIG_RECEIVED    1

typedef struct signal_stat
{
    int sent;
    int received;
} signal_stat;

struct signal_ent
{
    int signum;
    const char* sig_name;
};

void mark_sig(short action, struct trace_ctrl* ctrl, int signum);
void print_sig_stats(struct trace_ctrl** ctrls, int length);

static const int sigents_len = 31;
static const struct signal_ent sigents[] =
{
    { SIGHUP, "SIGHUP" },
    { SIGINT, "SIGINT" },
    { SIGQUIT, "SIGQUIT" },
    { SIGILL, "SIGILL" },
    { SIGTRAP, "SIGTRAP" },
    { SIGABRT, "SIGABRT" },
    { SIGBUS, "SIGBUS" },
    { SIGFPE, "SIGFPE" },
    { SIGKILL, "SIGKILL" },
    { SIGUSR1, "SIGUSR1" },
    { SIGSEGV, "SIGSEGV" },
    { SIGUSR2, "SIGUSR2" },
    { SIGPIPE, "SIGPIPE" },
    { SIGALRM, "SIGALRM" },
    { SIGTERM, "SIGTERM" },
    { SIGSTKFLT, "SIGSTKFLT" },
    { SIGCHLD, "SIGCHLD" },
    { SIGCONT, "SIGCONT" },
    { SIGSTOP, "SIGSTOP" },
    { SIGTSTP, "SIGTSTP" },
    { SIGTTIN, "SIGTTIN" },
    { SIGTTOU, "SIGTTOU" },
    { SIGURG, "SIGURG" },
    { SIGXCPU, "SIGXCPU" },
    { SIGXFSZ, "SIGXFSZ" },
    { SIGVTALRM, "SIGVTALRM" },
    { SIGPROF, "SIGPROF" },
    { SIGWINCH, "SIGWINCH" },
    { SIGIO, "SIGIO" },
    { SIGPWR, "SIGPWR" },
    { SIGSYS, "SIGSYS" }
};

#endif /* __SIGSTAT_H__ */
