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
#include "sigstat.h"

struct signal_stat*
alloc_sig_stats()
{
    struct signal_stat* stats_tab = (struct signal_stat*) calloc(SIGNALS_COUNT, sizeof(struct signal_stat));
    return stats_tab;
}

void
mark_sig(short action, struct trace_ctrl* ctrl, int signum)
{
    struct signal_stat* stat = &ctrl->signal_stats[signum];
    if (action == SIG_SENT) {
        stat->sent++;
    }

    else {
        stat->received++;
    }
}

void print_sig_stats(struct trace_ctrl** ctrls, int length)
{
    int i, j;
    struct trace_ctrl* ctrl;

    printf("[sigstat] Signal statistics\n");
    printf("[?] Format: SIGNAME (signum)\tsent\treceived\n");

    for (i = 0; i < length; i++)
    {
        if (ctrls[i]->pid == 0)
            continue;

        ctrl = ctrls[i];
        printf("[*] PID: %d\n", ctrl->print_pid);

        for (j = 0; j < SIGNALS_COUNT; j++)
        {
            if (ctrl->signal_stats[j].sent != 0 || ctrl->signal_stats[j].received != 0)
            {
                printf("%s (%d)\t%d\t%d\n", sigents[j].sig_name, j, ctrl->signal_stats[j].sent, ctrl->signal_stats[j].received);
            }
        }
    }
}
