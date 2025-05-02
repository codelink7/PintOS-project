#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>

void syscall_init (void);
int is_valid_user_pointer(const void *uaddr);
void syscall_halt(void);
void syscall_exit(int status);
tid_t syscall_exec(struct intr_frame *);
int syscall_wait(struct intr_frame *);
bool syscall_create(struct intr_frame *);
bool syscall_remove(struct intr_frame *);
int syscall_open(struct intr_frame *);
int syscall_filesize(struct intr_frame *);
int syscall_read(struct intr_frame *);
int syscall_write(struct intr_frame *);
void syscall_seek(struct intr_frame *);
unsigned syscall_tell(struct intr_frame *);
void syscall_close(struct intr_frame *);

#endif /* userprog/syscall.h */
