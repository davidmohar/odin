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
#ifndef FILE_ENT_H_INCLUDED
#define FILE_ENT_H_INCLUDED

#include <stdlib.h>
#include <sys/types.h>

#define DEF_FILE_ENT_LEN 4
struct fd_to_file_ent;
struct fd_to_file_ent
{
    int fd_no;
    struct file_ent* file_ent;
    /* Implementing a list */
    struct fd_to_file_ent* next;
};

struct file_ent
{
    ino_t inode_no;
    int fd_no;
    char* filename;
    int opens;
    int closes;
    long reads;
    long writes;
};

#endif // FILE_ENT_H_INCLUDED
