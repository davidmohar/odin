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
#include "file_ent.h"

void
destroy_fd_mappings(struct fd_to_file_ent* list)
{
    if (list == NULL)
        return;

    destroy_fd_mappings(list->next);
    free(list);
}

struct fd_to_file_ent*
remove_fd_mapping(int fd_no, struct fd_to_file_ent* list)
{
    if (list == NULL)
        return NULL;

    if (list->fd_no == fd_no)
    {
        struct fd_to_file_ent* next = list->next;
        free(list);

        return next;
    }

    list->next = remove_fd_mapping(fd_no, list->next);
    return list;
}

struct fd_to_file_ent*
add_fd_mapping(int fd_no, struct file_ent* file_ent, struct fd_to_file_ent* list)
{
    int i;

    if (list == NULL)
    {
        list = (struct fd_to_file_ent*) malloc(sizeof(struct fd_to_file_ent));
        memset(list, 0, sizeof(struct fd_to_file_ent));

        list->fd_no = fd_no;
        list->file_ent = file_ent;
        list->next = NULL;

        return list;
    }

    list->next = add_fd_mapping(fd_no, file_ent, list->next);
    return list;
}

struct file_ent*
find_file_ent(struct fd_to_file_ent* list, int fd_no)
{
    if (list == NULL)
        return NULL;

    if (list->fd_no == fd_no)
        return list->file_ent;

    return find_file_ent(list->next, fd_no);
}

struct file_ent*
find_file_ent_ino(ino_t ino, struct file_ent** tab, int num_files)
{
    int i;
    for (i = 0; i < num_files; i++)
    {
        if (tab[i]->inode_no == ino)
            return tab[i];
    }

    return NULL;
}

void
destroy_file_ent_tab(struct file_ent** tab, int size)
{
    int i;
    for (i = 0; i < size; i++)
    {
        free(tab[i]->filename);
        free(tab[i]);
    }

    free(tab);
}

struct file_ent**
create_file_ent_tab(int* size)
{
    int len = DEF_FILE_ENT_LEN;
    struct file_ent** new_tab = (struct file_ent**) calloc(len, sizeof(struct file_ent*));

    if (!new_tab)
        die("create_file_ent_tab: out of memory");

    *size = len;
    len = 0;
    /* Copy over new pointers */
    while (len < *size)
        new_tab[len++] = NULL;

    return new_tab;
}

struct file_ent**
grow_file_ent_tab(struct file_ent** tab, int* size)
{
    int i = 0;
    int len = *size;
    /* Reallocate */
    struct file_ent** new_tab = (struct file_ent**) realloc(tab, len * 2 * sizeof(tab[0]));

    if (!new_tab)
        die("grow_file_ent_tab: out of memory");

    (*size) *= 2;
    /* Copy over new pointers and null others */
    while (i < len)
        new_tab[i++] = tab[i];

    while (i < *size)
        new_tab[i++] = NULL;

    return new_tab;
}

struct file_ent**
add_file_ent(struct file_ent* ent, struct file_ent** tab, int* tab_len, int* num_files)
{
    int i;
    struct file_ent** ent_tab = tab;

    if (*tab_len == 0)
        ent_tab = create_file_ent_tab(tab_len);

    if (*num_files == *tab_len)
        ent_tab = grow_file_ent_tab(tab, tab_len);

    for (i = 0; i < *tab_len; i++)
    {
        if (ent_tab[i] == NULL)
        {
            ent_tab[i] = ent;
            (*num_files)++;

            return ent_tab;
        }
    }

    die("add_file_ent: bug!");
    return NULL;
}
