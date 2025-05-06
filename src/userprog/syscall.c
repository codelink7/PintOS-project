#include "userprog/syscall.h"
#include <stdio.h>
#include <stdlib.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "lib/stdio.h"


static void syscall_handler (struct intr_frame *);
void syscall_halt(void);
void syscall_exit(int status);
tid_t syscall_exec(struct intr_frame *);
int syscall_wait(struct intr_frame *);
bool syscall_create(struct intr_frame *);
bool syscall_remove(struct intr_frame *);
void syscall_open(struct intr_frame *);
int syscall_filesize(struct intr_frame *);
int syscall_read(struct intr_frame *);
int syscall_write(struct intr_frame *);
void syscall_seek(struct intr_frame *);
unsigned syscall_tell(struct intr_frame *);
void syscall_close(struct intr_frame *);

/*
  We only use one lock because we're protecting the 
  structure that is shared between the files not the content of the files itself
*/

static struct lock locker_for_all_files; 


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
        syscall_wait(f);
        break;
      case SYS_CREATE:
        f->eax = syscall_create(f);
        break;
      case SYS_REMOVE:
        f->eax = syscall_remove(f);
        break;
      case SYS_OPEN:
        syscall_open(f);
        break;
      case SYS_FILESIZE:
        f->eax = syscall_filesize(f);
        break;
      case SYS_READ:
        f->eax = syscall_read(f);
        break;
      case SYS_WRITE:
        f->eax = syscall_write(f);
        break;
      case SYS_SEEK:
        syscall_seek(f);
        break;
      case SYS_TELL:
        f->eax = syscall_tell(f);
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

// Here's the key idea:

// Even if different threads access different files, 
// they all use the same shared file system structures like inode tables, 
// file descriptor tables, or directory trees. These structures must be protected.

// So even if you're opening fileA.txt and someone else is writing to fileB.txt, they both:

// Might allocate an inode,

// Might read or update metadata (like open counts, file positions),

// Might trigger disk I/O.

// This is why a global lock is used to protect the critical section across all file operations.

void syscall_open(struct intr_frame *f){
  if (!is_valid_user_pointer(f->esp + 4)) syscall_exit(-1);
  char *filename = *(char **)(f->esp + 4);
  if (filename == NULL) syscall_exit(-1);
  struct opened_file_struct *opened_file = (struct opened_file_struct*) malloc(
    sizeof(struct opened_file_struct)
  );
  if (opened_file == NULL) return -1; // The file wasn't opened and we returned zero which is not a valid descriptor
  lock_acquire(&locker_for_all_files);
  opened_file->ptr = filesys_open(filename);
  lock_release(&locker_for_all_files);
  opened_file->fd = ++thread_current()->last_file_descriptor;
  list_push_back(&thread_current()->opened_files_list, &opened_file->elem);
  f->eax = opened_file->fd;
}

bool syscall_remove(struct intr_frame *f){
  if (!is_valid_user_pointer(f->esp + 4)) syscall_exit(-1);
  char *filename = *(char **)(f->esp + 4);
  if (filename == NULL || is_valid_user_pointer(filename)) syscall_exit(-1);
  bool removing_result;
  lock_acquire(&locker_for_all_files);
  removing_result = filesys_remove(filename);
  lock_release(&locker_for_all_files);
  return removing_result;
}

int syscall_filesize(struct intr_frame *f){
  if (!is_valid_user_pointer(f->esp + 4)) syscall_exit(-1);
  int file_descriptor = *(int *)(f->esp + 4);
  uint32_t file_length_uint32_t;
  struct opened_file_struct *opened_file = get_open_file_by_fd(file_descriptor);
  if (opened_file == NULL) return -1;
  lock_acquire(&locker_for_all_files);
  file_length_uint32_t = (uint32_t)file_length(opened_file);
  lock_release(&locker_for_all_files);
  return file_length_uint32_t;
}

// bool create (const char *file, unsigned initial_size)
// bool filesys_create (const char *name, off_t initial_size);

// So, f->esp + 4 contains the value of the filename pointer — 
// but that pointer itself points to a string in user memory.

// 🔎 Step-by-Step Dissection
// (char **)(f->esp + 4)
// f->esp + 4:
// This moves 4 bytes up the stack to where the first argument is stored (the filename pointer).

// (char **):
// You cast it to char **, meaning:

// "Interpret this address as a pointer to a char *"

// Because the user put a char * on the stack.

// *(char **):
// Now you dereference it — you go to that memory location, and grab the char * value stored there.

// In other words: you're pulling out the actual address of the filename string.

bool syscall_create(struct intr_frame *f){
  if (!is_valid_user_pointer(f->esp + 4)) syscall_exit(-1);
  if (!is_valid_user_pointer(f->esp + 8)) syscall_exit(-1);
  char *filename = *(char **)(f->esp + 4);
  size_t inital_file_length = *(unsigned *)(f->esp + 8);
  bool creating_result;
  if (filename == NULL || !is_valid_user_pointer(filename))
    return false;
  lock_acquire(&locker_for_all_files);
  creating_result = (bool)filesys_create(filename, inital_file_length);
  lock_release(&locker_for_all_files);
  return creating_result;
}

// file_close (struct file *file) 
void syscall_close(struct intr_frame *f){
  if (!is_valid_user_pointer(f->esp + 4)) syscall_exit(-1);
  int file_descriptor = *(int *)(f->esp + 4);
  struct opened_file_struct *file_to_be_closed = get_open_file_by_fd(file_descriptor);
  if (file_to_be_closed == NULL) return;
  lock_acquire(&locker_for_all_files);
  file_close (file_to_be_closed->ptr);
  lock_release(&locker_for_all_files);
  list_remove(&file_to_be_closed->elem);
  palloc_free_page(file_to_be_closed);
}

unsigned syscall_tell(struct intr_frame *f){
  if (!is_valid_user_pointer(f->esp + 4)) syscall_exit(-1);
  int file_descriptor = *(int *)(f->esp + 4);
  uint32_t telling_file_result;
  struct opened_file_struct *file_to_be_telled = get_open_file_by_fd(file_descriptor);
  if (file_to_be_telled == NULL) return (unsigned) -1;
  lock_acquire(&locker_for_all_files);
  telling_file_result = file_tell(file_to_be_telled->ptr);
  lock_release(&locker_for_all_files);
  return telling_file_result;
}

void syscall_seek(struct intr_frame *f){
  if (!is_valid_user_pointer(f->esp + 4)) syscall_exit(-1);
  if (!is_valid_user_pointer(f->esp + 8)) syscall_exit(-1);
  int file_descriptor = *(int *)(f->esp + 4);
  uint32_t position_to_be_seeked = *(int *)(f->esp + 8);
  struct opened_file_struct *file_to_be_seeked = get_open_file_by_fd(file_descriptor);
  if (file_to_be_seeked == NULL) return;
  lock_acquire(&locker_for_all_files);
  file_seek(file_to_be_seeked->ptr, position_to_be_seeked);
  lock_release(&locker_for_all_files);
}

// void *buffer = *(void **)(f->esp + 8);  // 3rd argument
// That means:

// The user passed a char * as the buffer

// That pointer is stored on the stack at f->esp + 8

// You retrieve it using a double pointer (void **), then dereference to get the real buffer address

// 🔹 ((char *)buffer)[i]
// This accesses the i-th byte of the buffer.

// Think of buffer as an array of bytes: you're writing into the i-th position.
// So:
// ((char *)buffer)[0] = first character from input
// ((char *)buffer)[1] = second character from input

// off_t
// file_read (struct file *file, void *buffer, off_t size) 

int syscall_read(struct intr_frame *f){
  if (!is_valid_user_pointer(f->esp + 4)) syscall_exit(-1);
  if (!is_valid_user_pointer(f->esp + 8)) syscall_exit(-1);
  if (!is_valid_user_pointer(f->esp + 12)) syscall_exit(-1);
  int file_descriptor = *(int *)(f->esp + 4);
  void *buffer = *(void **)(f->esp + 8);
  uint32_t size_to_be_read = *(int *)(f->esp + 12);
  if (buffer == NULL || !is_valid_user_pointer(buffer))
    return -1;
  if (file_descriptor == STDIN_FILENO){
    for (int i = 0; i < size_to_be_read; i++){
      lock_acquire(&locker_for_all_files);
      ((char*)buffer)[i] = input_getc();
      lock_release(&locker_for_all_files);
    }
    return size_to_be_read;
  } else {
    struct opened_file_struct *file_to_be_read = get_open_file_by_fd(file_descriptor);
    if (file_to_be_read == NULL) -1;
    int read_result;
    lock_acquire(&locker_for_all_files);
    read_result = file_read(file_to_be_read->ptr, buffer, size_to_be_read);
    lock_release(&locker_for_all_files);
    return read_result;
  }
}

// void
// putbuf (const char *buffer, size_t n) 

// off_t
// file_write (struct file *file, const void *buffer, off_t size) 
int syscall_write(struct intr_frame *f){
  if (!is_valid_user_pointer(f->esp + 4)) syscall_exit(-1);
  if (!is_valid_user_pointer(f->esp + 8)) syscall_exit(-1);
  if (!is_valid_user_pointer(f->esp + 12)) syscall_exit(-1);
  int file_descriptor = *(int *)(f->esp + 4);
  void *buffer = *(void **)(f->esp + 8);
  uint32_t size_to_be_written = *(int *)(f->esp + 12);
  if (buffer == NULL || !is_valid_user_pointer(buffer))
    return -1;
  if (file_descriptor == STDIN_FILENO){
    lock_acquire(&locker_for_all_files);
    putbuf(buffer, size_to_be_written);
    lock_release(&locker_for_all_files);
    return size_to_be_written;
  } else {
    struct opened_file_struct *file_to_be_written_to = get_open_file_by_fd(file_descriptor);
    if (file_to_be_written_to == NULL) -1;
    int write_result;
    lock_acquire(&locker_for_all_files);
    write_result = file_write(file_to_be_written_to->ptr, buffer, size_to_be_written);
    lock_release(&locker_for_all_files);
    return write_result;
  }
}

struct opened_file_struct *get_open_file_by_fd(int fd) {
  struct list_elem *e;
  struct thread *t = thread_current();
  for (e = list_begin(&t->opened_files_list); e != list_end(&t->opened_files_list); e = list_next(e)) {
      struct opened_file_struct *of = list_entry(e, struct opened_file_struct, elem);
      if (of->fd == fd)
          return of;
  }
  return NULL;
}

int syscall_wait(struct intr_frame *f){
  return 1;
}

tid_t syscall_exec(struct intr_frame *f){
  return 1;
}

// sudo docker run --platform linux/amd64 --rm -it -v "$(pwd)/PintOS-project:/root/pintos" /* */