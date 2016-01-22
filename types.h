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
#ifndef _TYPES_H_
#define _TYPES_H_

#include <time.h>

#include "sigstat.h"

#define TC_OK           0x00
#define TC_INIT         0x01
#define TC_ATTACHED     0x02
#define TC_INSYSCALL    0x04

#ifndef MAX_ARGS
#  define MAX_ARGS	6
#endif

#define SIGNALS_COUNT   31
#define SYSCALL_COUNT   317

struct trace_ctrl
{
    int pid;
    int renum_pid;
    int print_pid;
    int parent;
    int status;
    int exit_status;
    /* Statistics */
    int lastsyscall;

    clock_t start_time;
    clock_t end_time;

    double running_time;

    struct fd_to_file_ent* fd_mappings;

    struct file_ent** file_ents;
    int file_ents_count;
    int num_files;

    int syscall_stat[SYSCALL_COUNT];
    struct signal_stat* signal_stats;
};

#define entering(ctrl)  (!((ctrl)->status & TC_INSYSCALL))
#define exiting(ctrl)   ((ctrl)->status & TC_INSYSCALL)

struct exec_params
{
    char* pathname;
    char** argv;
};

struct syscall_ent
{
    unsigned nargs;
    int sys_flags;
    const char* func_name;
};

struct syscall_stat
{
    int syscallnum;
    int call_count;
};

#endif
