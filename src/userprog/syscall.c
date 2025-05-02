#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
static void syscall_handler (struct intr_frame *);


void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/*
  f->esp points to the syscall number

  f->esp + 4 points to the first argument

  f->esp + 8 → second argument

  f->esp + 12 → third argument
For:
c
  write(fd, buffer, size);
  syscall number: at f->esp

  fd: at f->esp + 4

  buffer: at f->esp + 8

  size: at f->esp + 12
*/

// * You have to validate the pointer you use 
static void
syscall_handler (struct intr_frame *f) 
{
  printf ("system call!\n");
  if (!is_valid_user_pointer(f->esp)) syscall_exit(-1);
  int sys_call_num = *(int *)f->esp;
  switch(sys_call_num){
    case SYS_HALT:
        syscall_halt();
        break;
      case SYS_EXIT:
        if (!is_valid_user_pointer(f->esp + 4)) syscall_exit(-1);
        syscall_exit(*(int *)(f->esp + 4));
        break;
      case SYS_EXEC:
        syscall_exec(f);
        break;
      case SYS_WAIT:
        sys_wait(f);
        break;
      case SYS_CREATE:
        syscall_create(f);
        break;
      case SYS_REMOVE:
        syscall_remove(f);
        break;
      case SYS_OPEN:
        syscall_open(f);
        break;
      case SYS_FILESIZE:
        syscall_filesize(f);
        break;
      case SYS_READ:
        syscall_read(f);
        break;
      case SYS_WRITE:
        syscall_write(f);
        break;
      case SYS_SEEK:
        syscall_seek(f);
        break;
      case SYS_TELL:
        syscall_tell(f);
        break;
      case SYS_CLOSE:
        syscall_close(f);
        break;
      default:
        syscall_exit(-1);
        break;
  }

}

int
is_valid_user_pointer(const void *uaddr)
{
  if (uaddr != NULL && is_user_vaddr(uaddr) && 
  pagedir_get_page(thread_current()->pagedir, uaddr) != NULL) return 1;
  else return 0;
}

void syscall_halt(){
  shutdown_power_off();
}

// ((int *)f->esp + 1) moves 4 bytes forward, to point at the first argument
// *((int *)f->esp + 1) dereferences that pointer to get the int status

void syscall_exit(int status){
  struct thread *cur = thread_current();
  struct thread *parent = cur->parent_thread;
  cur->exit_status = status;
  printf("%s: exit(%d)\n", cur->name, status);
  if (parent != NULL) parent->child_exit_status = status;
  thread_exit();
}
