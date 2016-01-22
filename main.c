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
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <time.h>

#include <bits/types.h>

#include <sys/types.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include "types.h"
#include "syscall.h"
#include "file_ent.h"
#include "sigstat.h"

#define TC_DEF_LEN 2

#define PROCINSYSCALL(proc) \
    (proc->status & TC_INSYSCALL) == TC_INSYSCALL

static short verbose_output = 0;
static short print_signals = 0;
static short print_process_tree = 0;
static short print_syscall_stats = 0;
static short print_process_times = 0;
static short print_file_usage = 0;
static short print_pid_mappings = 0;
static short renumber_pids = 0;
static int renumber_pid_seed = 0;

static int odin_pid = 0;

static char* stdin_redirect = NULL;
static char* stdout_redirect = NULL;
static char* stderr_redirect = NULL;

static struct trace_ctrl** tctrl_tab;
static unsigned int num_procs = 0, tctrl_len = 0;

static long ptrace_options = PTRACE_O_TRACEEXIT  |
                             PTRACE_O_TRACEFORK  |
                             PTRACE_O_TRACEVFORK |
                             PTRACE_O_TRACECLONE |
                             PTRACE_O_TRACESYSGOOD;

/* Statistics for syscall count */
static int stats_len = 17;
static struct syscall_stat stats_tab[] =
{
    { 0,    0 },    /* read */
    { 1,    0 },    /* write */
    { 2,    0 },    /* open */
    { 3,    0 },    /* close */
    { 4,    0 },    /* stat */
    { 21,   0 },    /* access */
    { 56,   0 },    /* clone */
    { 79,   0 },    /* getcwd */
    { 80,   0 },    /* chdir */
    { 82,   0 },    /* rename */
    { 83,   0 },    /* mkdir */
    { 84,   0 },    /* rmdir */
    { 86,   0 },    /* link */
    { 87,   0 },    /* unlink */
    { 88,   0 },    /* symlink */
    { 89,   0 },    /* readlink */
    { 90,   0 },    /* chmod */
    { 92,   0 }     /* chown */
};

static void cleanup(void);

void
die(const char* msg)
{
    if (odin_pid == getpid())
        cleanup();

    printf("%s\n", msg);
    exit(1);
}

static int
ptrace_attach(int pid)
{
    int r = ptrace(PTRACE_ATTACH, pid, 0L, 0L);
    ptrace(PTRACE_SETOPTIONS, pid, 0L, ptrace_options);

    return r;
}

static void
mark_syscall(int syscallnum)
{
    int i;
    for (i = 0; i < stats_len; i++)
    {
        struct syscall_stat* stat = &stats_tab[i];
        if (stat->syscallnum == syscallnum)
        {
            stat->call_count++;
        }
    }
}

static struct file_ent*
create_file_ent(int fd, ino_t inode, char* filename)
{
    struct file_ent* file_ent = (struct file_ent*) malloc(sizeof(struct file_ent));
    file_ent->fd_no = fd;
    file_ent->filename = filename;
    file_ent->inode_no = inode;
    file_ent->opens = file_ent->closes = 0;

    return file_ent;
}

static void
mark_open(struct trace_ctrl* ctrl, int fd)
{
    long file_ptr;
    char* filename;

    struct file_ent* file_ent;
    struct fd_to_file_ent* map_ent;

    struct stat file_stat;
    memset(&file_stat, 0, sizeof(struct stat));

    /* Try to find an existing FD->INODE mapping.
     * If not found, extract filename from syscall to stat
     * and add a new mapping.
     */
    file_ent = find_file_ent(ctrl->fd_mappings, fd);
    if (file_ent == NULL)
    {
        file_ptr = syscall_arg(ctrl->pid, 0);
        filename = syscall_read_str(ctrl->pid, file_ptr);

        stat(filename, &file_stat);
        file_ent = find_file_ent_ino(file_stat.st_ino, ctrl->file_ents, ctrl->num_files);
        if (file_ent == NULL)
        {
            file_ent = create_file_ent(fd, file_stat.st_ino, filename);
            ctrl->file_ents = add_file_ent(file_ent, ctrl->file_ents, &ctrl->file_ents_count, &ctrl->num_files);
        }

        ctrl->fd_mappings = add_fd_mapping(fd, file_ent, ctrl->fd_mappings);
    }

    file_ent->opens++;
}

static void
mark_file_read(struct trace_ctrl* ctrl, int fd, int bytes_read)
{
    struct file_ent* file = find_file_ent(ctrl->fd_mappings, fd);
    if (file == NULL)
        die("mark_file_read: file should be found");

    file->reads += bytes_read;
}

static void
mark_file_write(struct trace_ctrl* ctrl, int fd, int bytes_wrote)
{
    if (fd < 3)
        return;

    struct file_ent* file = find_file_ent(ctrl->fd_mappings, fd);
    if (file == NULL)
        die("mark_file_write: file should be found");

    file->writes += bytes_wrote;
}

static void
mark_close(struct trace_ctrl* ctrl, int fd)
{
    if (fd < 3)
        return;

    struct file_ent* file_ent = find_file_ent(ctrl->fd_mappings, fd);
    if (file_ent == NULL)
        return;

    file_ent->closes++;
    ctrl->fd_mappings = remove_fd_mapping(fd, ctrl->fd_mappings);
}

static void
cleanup(void)
{
    int i, j;
    struct trace_ctrl* ctrl;
    for (i = 0; i < tctrl_len; i++)
    {
        ctrl = tctrl_tab[i];
        if (ctrl->pid)
        {
            destroy_fd_mappings(ctrl->fd_mappings);
            destroy_file_ent_tab(ctrl->file_ents, ctrl->num_files);
        }

        //free(tctrl_tab[i]);
    }

    //free(tctrl_tab);
}

static void
create_tctrl_tab()
{
    int len = TC_DEF_LEN;
    struct trace_ctrl* new_ctrls = (struct trace_ctrl*) calloc(len, sizeof(new_ctrls[0]));
    struct trace_ctrl** new_tab = (struct trace_ctrl**) calloc(len, sizeof(tctrl_tab[0]));

    if (!new_ctrls || !new_tab)
        die("create_tctrl_tab: out of memory");
    tctrl_len = len;
    len = 0;
    tctrl_tab = new_tab;
    /* Copy over new pointers */
    while (len < tctrl_len)
        tctrl_tab[len++] = new_ctrls++;
}

static void
expand_tctrl_tab()
{
    int len = tctrl_len;
    /* Reallocate */
    struct trace_ctrl* new_ctrls = (struct trace_ctrl*) calloc(len, sizeof(new_ctrls[0]));
    struct trace_ctrl** new_tab = (struct trace_ctrl**) realloc(tctrl_tab, len * 2 * sizeof(tctrl_tab[0]));

    if (!new_ctrls || !new_tab)
        die("expand_tctrl_tab: out of memory");
    tctrl_len *= 2;
    tctrl_tab = new_tab;
    /* Copy over new pointers */
    while (len < tctrl_len)
        tctrl_tab[len++] = new_ctrls++;
}

/*static void
dealloc_ctrl(struct trace_ctrl* ctrl)
{
    if (ctrl->pid == 0)
        return;

    num_procs--;
    memset(ctrl, 0, sizeof(*ctrl));
}*/

static struct trace_ctrl*
alloc_ctrl(int pid, int parent)
{
    int i;
    struct trace_ctrl* ctrl;

    if (tctrl_len == 0)
        create_tctrl_tab();

    if (num_procs == tctrl_len)
        expand_tctrl_tab();

    for (i = 0; i < tctrl_len; i++)
    {
        ctrl = tctrl_tab[i];
        if (!ctrl->pid)
        {
            memset(ctrl, 0, sizeof(*ctrl));
            ctrl->pid = pid;
            ctrl->renum_pid = renumber_pid_seed++;
            ctrl->print_pid = (renumber_pids == 0) ? pid : ctrl->renum_pid;
            ctrl->parent = parent;
            ctrl->start_time = clock();

            ctrl->signal_stats = alloc_sig_stats();

            num_procs++;
            return ctrl;
        }
    }

    die("alloc_ctrl: bug!");
    return NULL;
}

static struct trace_ctrl*
pid2ctrl(int pid)
{
    int i;

    if (pid <= 0)
        return NULL;

    for (i = 0; i < tctrl_len; i++)
    {
        struct trace_ctrl* ctrl = tctrl_tab[i];
        if (ctrl->pid == pid)
            return ctrl;
    }

    return NULL;
}

static void __attribute__ ((noinline, noreturn))
exec_or_die(int argc, char* argv[])
{
    int null_fd = open("/dev/null", O_RDWR);
    /* Redirects */
    int stdout_fd = (stdout_redirect != NULL) ? open(stdin_redirect, O_WRONLY) : null_fd;
    int stdin_fd = (stdin_redirect != NULL) ? open(stdin_redirect, O_RDONLY) : null_fd;
    int stderr_fd = (stderr_redirect != NULL) ? open(stdin_redirect, O_WRONLY) : null_fd;

    dup2(stdin_fd, STDIN_FILENO);
    dup2(stdout_fd, STDOUT_FILENO);
    dup2(stderr_fd, STDERR_FILENO);

    close(stdin_fd);
    close(stdout_fd);
    close(stderr_fd);
    /*if (stdin_redirect != NULL)
        close(stdin_fd);*/

    ptrace(PTRACE_TRACEME);
    kill(getpid(), SIGSTOP);

    /* We no longer have control :( */
    execvp(argv[0], argv);
    exit(1);
}

static int
parse_argv(int argc, char** argv)
{
    int i;
    char opt;
    char* next_char;

    /*
        getopt(3) treated optional target parameters as his own
        ex.: odin -v ./test -ab -f
    */
    for (i = 1; i < argc; i++)
    {
        if (*(argv[i]) != '-')
            return i;

        next_char = argv[i] + 1;
        while ((*next_char) != '\0')
        {
            opt = *next_char;
            switch (opt)
            {
                case 'v':
                    verbose_output = 1;
                    break;

                case 't':
                    print_process_times = 1;
                    /* Running times are printed with process tree (easier) */
                case 'p':
                    print_process_tree = 1;
                    break;

                case 'r':
                    renumber_pids = 1;
                    renumber_pid_seed = atoi(argv[i + 1]);
                    /* If true, the next argument is probably a number supplied
                       TODO: Negative numbers will cause a crash! */
                    if (argv[i + 1] == '0' || renumber_pid_seed != 0)
                        i++;

                    break;

                case 'm':
                    print_pid_mappings = 1;
                    break;

                case 's':
                    print_syscall_stats = 1;
                    break;

                case 'a':
                    print_signals = 1;
                    break;

                case 'f':
                    print_file_usage = 1;
                    break;

                case 'i':
                    stdin_redirect = argv[++i];
                    break;

                case 'o':
                    stdout_redirect = argv[++i];
                    break;

                case 'e':
                    stderr_redirect = argv[++i];
                    break;

                default:
                    die("parse_argv:unrecognized option");
            }

            next_char++;
        }
    }

    die("parse_argv:invalid arguments");
    return 0;
}

static void
file_usage_stats()
{
    int i, j;
    struct trace_ctrl* ctrl;
    struct file_ent* file_ent;

    printf("[filestat] File usage statistics\n");
    printf("[?] Format: file_name\tnum_opens\tnum_closes\tread (bytes)\twritten (bytes)\n");
    for (i = 0; i < tctrl_len; i++)
    {
        ctrl = tctrl_tab[i];
        if (!ctrl->pid)
            continue;

        printf("[*] PID: %d\n", ctrl->print_pid);
        if (ctrl->file_ents == NULL)
        {
            printf("no file usage\n");
            continue;
        }

        for (j = 0; j < ctrl->num_files; j++)
        {
            file_ent = ctrl->file_ents[j];
            if (file_ent == NULL)
                continue;

            /* Truncate long file paths for better readability */
            int fileName_len = strlen(file_ent->filename);
            char* fileName = fileName_len > 50 ? (file_ent->filename + fileName_len - 50) : file_ent->filename;
            printf("%-50s\t%d\t%d\t%ld\t%ld\n", fileName, file_ent->opens, file_ent->closes, file_ent->reads, file_ent->writes);
        }
    }
}

static void
syscall_stats()
{
    int i, j;

    printf("[callstat] Syscall Statistics\n");
    printf("[?] Format: syscall\tnum_calls\n");

    for (i = 0; i < tctrl_len; i++)
    {
        struct trace_ctrl* ctrl = tctrl_tab[i];
        printf("[*] PID: %d\n", ctrl->print_pid);

        for (j = 0; j < SYSCALL_COUNT; j++)
        {
            if (ctrl->syscall_stat[j] == 0)
                continue;

            printf("%s\t%d\n", sysents[j].func_name, ctrl->syscall_stat[j]);
        }
    }
}

static void
pid_mappings()
{
    int i;
    printf("[map] PID Mappings\n");
    printf("[?] Format: renumbered_pid -> original_pid\n");
    for (i = 0; i < tctrl_len; i++)
    {
        printf("%d -> %d\n", tctrl_tab[i]->renum_pid, tctrl_tab[i]->pid);
    }
}

static void
process_tree_rec(int parent, int depth)
{
    int i;
    /* Prepare leading lines */
    char* prepend = (char*) malloc((sizeof(char) * depth) + sizeof(char) + 1);
    memset(prepend, '-', sizeof(char) * depth);
    prepend[depth] = '\0';

    if (depth > 0)
    {
        prepend[depth] = ' ';
        prepend[depth + 1] = '\0';
    }

    /* Loop through trace_ctrls and print children */
    for (i = 0; i < tctrl_len; i++)
    {
        struct trace_ctrl* ctrl = tctrl_tab[i];
        /* End */
        if (!ctrl->pid)
        {
            free(prepend);
            return;
        }

        if (ctrl->pid == parent)
            continue;

        if (ctrl->parent == parent)
        {
            int pid = (renumber_pids == 1) ? ctrl->renum_pid : ctrl->pid;
            if (print_process_times) {
                printf("%s%d (%.2fms)\n", prepend, pid, ctrl->running_time);
            }
            else {
                printf("%s%d (exit status %d)\n", prepend, pid, ctrl->exit_status);
            }

            process_tree_rec(ctrl->pid, depth + 1);
        }
    }

    free(prepend);
}

static void
process_tree()
{
    printf("[proctree] Created Process Tree\n");
    process_tree_rec(0, 0);
}

static void
usage()
{
    printf("\
usage: odin [-ptsv] [-i file] PROG [ARGS]\n\
-p -- print process tree\n\
-r [num] -- renumber pids to starting number num (optional)\n\
-m -- print pid renumberings when using -r option\n\
-a -- display received signals\n\
-t -- display process running time (also enables -p)\n\
-s -- output syscall statistics (num. of calls)\n\
-f -- file usage statistics\n\
-v -- verbose output\n\
-i file -- redirects file to childs stdin\n\
-o file -- redirect stdout to file\n\
-e file -- redirects stderr to file\n");

    exit(0);
}

static void __attribute__ ((noinline))
init(int argc, char* argv[])
{
    if (argc < 2)
    {
        usage();
    }

    int pid, argv_offset;
    struct trace_ctrl* ctrl;

    signal(SIGCHLD, SIG_DFL);

    odin_pid = getpid();
    argv_offset = parse_argv(argc, argv);

    pid = fork();
    /* Child */
    if (!pid)
    {
        /* Execute child */
        exec_or_die(argc - argv_offset, argv + argv_offset);
    }

    /* Parent */
    ctrl = alloc_ctrl(pid, 0);
    ctrl->status |= TC_INIT;
}

static void
trace()
{
    if (verbose_output)
    {
        printf("[syscalls] Live System Calls\n");
        printf("[?] Format: syscall(numargs) = result, ex.: open(3) = 12\n");
    }

    while (1)
    {
        int pid, status, signum;
        long syscallnum, syscallresult;
        struct trace_ctrl* proc;

        /* We're done */
        if (num_procs == 0)
            break;

        pid = waitpid(-1, &status, 0);
        if (pid < 0)
        {
            perror("trace:waitpid");
            return;
        }

        proc = pid2ctrl(pid);
        if ((proc->status & TC_INIT) == TC_INIT)
        {
            ptrace(PTRACE_SETOPTIONS, pid, 0, ptrace_options);
            proc->status &= ~TC_INIT;
        }

        if (WIFSTOPPED(status))
        {
            signum = WSTOPSIG(status);
            /* SYSCALL */
            if (signum & 0x80)
            {
                if (PROCINSYSCALL(proc))
                {
                    syscallresult = get_reg(pid, eax);
                    syscallnum = get_reg(pid, orig_eax);

                    proc->syscall_stat[syscallnum]++;
                    //printf("SysCall: %ld | Result: %ld\n", syscallnum, syscallresult);

                    /* Fork! Let's hope we didn't miss something (clone, fork, vfork) */
                    if (syscallnum == 56 || syscallnum == 57 || syscallnum == 58)
                    {
                        ptrace_attach(syscallresult);
                        alloc_ctrl(syscallresult, pid);
                    }
                    /* open */
                    else if (syscallnum == 2)
                    {
                        mark_open(proc, syscallresult);
                    }
                    /* close - fd is passed in as first argument */
                    else if (syscallnum == 3)
                    {
                        int closed_fd = syscall_arg(pid, 0);
                        mark_close(proc, closed_fd);
                    }
                    /* read */
                    else if (syscallnum == 0)
                    {
                        int fd = syscall_arg(pid, 0);
                        mark_file_read(proc, fd, syscallresult);
                    }
                    /* write */
                    else if (syscallnum == 1)
                    {
                        int fd = syscall_arg(pid, 0);
                        mark_file_write(proc, fd, syscallresult);
                    }
                    /* kill */
                    else if (syscallnum == 62)
                    {
                        int kill_pid = syscall_arg(pid, 0);
                        int kill_signal = syscall_arg(pid, 1);

                        mark_sig(SIG_SENT, proc, kill_signal);
                        if (verbose_output)
                        {
                            printf("[%d] Signal %s -> %d\n", proc->print_pid, get_signame(kill_signal), kill_pid);
                        }
                    }

                    if (verbose_output)
                        printf("[%d] %s(%d) = %ld\n", proc->print_pid, sysents[syscallnum].func_name, sysents[syscallnum].nargs, syscallresult);
                }

                else
                {
                    syscallnum = get_reg(pid, orig_eax);
                    proc->lastsyscall = syscallnum;
                    proc->exit_status = syscall_arg(pid, 0);
                    proc->end_time = clock();
                    /* Handle exit seperately because we never return from exit */
                    if (verbose_output && syscallnum == 231)
                    {
                        printf("[%d] %s(%d) = ?\n", proc->print_pid, sysents[231].func_name, proc->exit_status);
                    }

                    mark_syscall(syscallnum);
                }

                proc->status ^= TC_INSYSCALL;
            }
            /* SIGNAL */
            else
            {
                if (print_signals)
                    printf("[%d] >> %s <<\n", proc->print_pid, get_signame(signum));

                mark_sig(SIG_RECEIVED, proc, signum);
            }
        }

        if (WIFEXITED(status))
        {
            num_procs--;
            proc->running_time = (double)(clock() - proc->start_time) * 1000 / CLOCKS_PER_SEC;
            /* Double check if it's time to exit because we don't want to call ptrace on a non-existing child */
            if (num_procs == 0)
                break;
        }

        ptrace(PTRACE_SYSCALL, pid, 0, 0);
    }

    if (verbose_output)
        printf("\n");
}

static void
print_output()
{
    if (print_process_tree)
    {
        process_tree();
        printf("\n");
    }

    if (print_syscall_stats)
    {
        syscall_stats();
        printf("\n");
    }

    if (print_file_usage)
    {
        file_usage_stats();
        printf("\n");
    }

    if (print_pid_mappings)
    {
        pid_mappings();
        printf("\n");
    }

    print_sig_stats(tctrl_tab, tctrl_len);
}

int
main(int argc, char* argv[])
{
    /* Configure tracing and spawn our child process */
    init(argc, argv);
    /* Main tracing loop */
    trace();
    /* Print all required output */
    print_output();
    /* Hide all evidence :) */
    cleanup();

    /* Hooray! */
    return 0;
}
