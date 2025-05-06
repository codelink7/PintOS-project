#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#include "threads/thread.h"

void syscall_init (void);
int is_valid_user_pointer(const void *uaddr);
struct opened_file_struct *get_open_file_by_fd(int);

#endif /* userprog/syscall.h */
