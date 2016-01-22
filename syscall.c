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
#include "syscall.h"

long
__get_reg(int pid, int offset)
{
    long val = ptrace(PTRACE_PEEKUSER, pid, offset);
    assert(errno == 0);

    return val;
}

long
syscall_arg(int pid, int argnum)
{
    switch (argnum)
    {
        #ifndef __amd64__
        case 0: return get_reg(pid, ebx);
        case 1: return get_reg(pid, ecx);
        case 2: return get_reg(pid, edx);
        case 3: return get_reg(pid, esi);
        case 4: return get_reg(pid, edi);
        case 5: return get_reg(pid, ebp);
        #else
        case 0: return get_reg(pid, rdi);
        case 1: return get_reg(pid, rsi);
        case 2: return get_reg(pid, rdx);
        case 3: return get_reg(pid, r10);
        case 4: return get_reg(pid, r8);
        case 5: return get_reg(pid, r9);
        #endif /* __amd64__ */
        default:
            return -1L;
    }
}

char*
syscall_read_str(int pid, unsigned long ptr)
{
    int read = 0, alloc = 4096;
    char* value = malloc(4096);
    unsigned long tmp;

    while (1)
    {
        if (read + sizeof(tmp) > alloc)
        {
            alloc = alloc * 2;
            value = realloc(value, alloc);
        }

        tmp = ptrace(PTRACE_PEEKDATA, pid, ptr + read);
        if (errno != 0)
        {
            value[read] = 0;
            break;
        }

        memcpy(value + read, &tmp, sizeof(tmp));
        if (memchr(&tmp, 0, sizeof(tmp)) != NULL)
            break;

        read += sizeof(tmp);
    }

    return value;
}

const char*
get_signame(int signum)
{
    int i;
    for (i = 0; i < sigents_len; i++)
    {
        if (sigents[i].signum == signum)
            return sigents[i].sig_name;
    }

    return NULL;
}
