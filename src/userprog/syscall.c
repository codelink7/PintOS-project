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
uint32_t syscall_filesize(struct intr_frame *);
int syscall_read(struct intr_frame *);
int syscall_write(struct intr_frame *);
void syscall_seek(struct intr_frame *);
unsigned syscall_tell(struct intr_frame *);
void syscall_close(struct intr_frame *);


static struct lock locker_for_all_files; 

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");

  // Initing the lock
  lock_init(&locker_for_all_files);
}

/*
  This is how we can get the arguments for every syscall we make

    f->esp points to the syscall number
    
    f->esp + 4 points to the first argument

    f->esp + 8 → second argument

    f->esp + 12 → third argument

For:
    write(fd, buffer, size);
    syscall number: at f->esp

    fd: at f->esp + 4

    buffer: at f->esp + 8

    size: at f->esp + 12
*/

// * You have to validate the pointer you use, This should be done in every syscall
static void
syscall_handler (struct intr_frame *f) 
{
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
        //ensure memory address of the pointer is valid
        f->eax = syscall_exec(f);
        break;
      case SYS_WAIT:
        f->eax = syscall_wait(f);
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

/* A function to validate if the pointer is valid to be referenced or not */
int
is_valid_user_pointer(const void *uaddr)
{
  if (uaddr != NULL && is_user_vaddr(uaddr) && 
  pagedir_get_page(thread_current()->pagedir, uaddr) != NULL) return 1;
  else return 0;
}

/* Halt implmentation */
void 
syscall_halt(){
  shutdown_power_off();
}

// ((int *)f->esp + 1) moves 4 bytes forward, to point at the first argument
// *((int *)f->esp + 1) dereferences that pointer to get the int status


/*
  We get the current process that we want to exit
  getting its parent, and assigning the status exit code
*/

void 
syscall_exit(int status){
  struct thread *cur = thread_current();
  struct thread *parent = cur->parent_thread;
  cur->exit_status = status;
  printf("%s: exit(%d)\n", cur->name, status);
  if (parent != NULL) parent->child_exit_status = status;
  thread_exit();
}

void
syscall_open(struct intr_frame *f){
  if (!is_valid_user_pointer(f->esp + 4)) syscall_exit(-1);
  char* name = (char*)(*((int*)f->esp + 1));
  if (name == NULL || !is_valid_user_pointer(name)) syscall_exit(-1);

  struct opened_file_struct *opened_file = palloc_get_page(0);
  if (opened_file == NULL) 
  {
    free(opened_file);
    f->eax = -1;
    return;
  }
  lock_acquire(&locker_for_all_files);
  opened_file->ptr = filesys_open(name);
  lock_release(&locker_for_all_files);
  if (opened_file->ptr == NULL)
  {
    f->eax = -1;
    return;
  }
  opened_file->fd = ++thread_current()->last_file_descriptor;
  list_push_back(&thread_current()->opened_files_list, &opened_file->elem);
  f->eax = opened_file->fd;
}

bool 
syscall_remove(struct intr_frame *f){
  if (!is_valid_user_pointer(f->esp + 4)) syscall_exit(-1);
  char *filename = *(char **)(f->esp + 4);
  if (filename == NULL || !is_valid_user_pointer(filename)) syscall_exit(-1);
  bool removing_result;
  lock_acquire(&locker_for_all_files);
  // bool filesys_remove (const char *name) 
  removing_result = filesys_remove(filename);
  lock_release(&locker_for_all_files);
  return removing_result;
}

uint32_t
syscall_filesize(struct intr_frame *f){
  if (!is_valid_user_pointer(f->esp + 4)) syscall_exit(-1);
  int file_descriptor = *(int *)(f->esp + 4);
  uint32_t file_length_uint32_t;
  struct opened_file_struct *opened_file = get_open_file_by_fd(file_descriptor);
  if (opened_file == NULL) return -1;
  lock_acquire(&locker_for_all_files);
  // off_t file_length (struct file *file) 
  file_length_uint32_t = (uint32_t) file_length(opened_file->ptr);
  lock_release(&locker_for_all_files);
  return file_length_uint32_t;
}



bool 
syscall_create(struct intr_frame *f){
  // Validation
  if (!is_valid_user_pointer(f->esp + 4)) syscall_exit(-1);
  if (!is_valid_user_pointer(f->esp + 8)) syscall_exit(-1);
  char *filename = *(char **)(f->esp + 4);
  size_t inital_file_length = *(unsigned *)(f->esp + 8);
  bool creating_result;
  if (filename == NULL || !is_valid_user_pointer(filename))
    syscall_exit(-1);
  lock_acquire(&locker_for_all_files);
  // bool create (const char *file, unsigned initial_size) -> The function in filesys.c
  creating_result = (bool) filesys_create(filename, inital_file_length);
  lock_release(&locker_for_all_files);
  return creating_result;
}


void 
syscall_close(struct intr_frame *f){
  if (!is_valid_user_pointer(f->esp + 4)) syscall_exit(-1);
  int file_descriptor = *(int *)(f->esp + 4);
  struct opened_file_struct *file_to_be_closed = get_open_file_by_fd(file_descriptor);
  if (file_to_be_closed == NULL) return;
    // file_close (struct file *file) 
  lock_acquire(&locker_for_all_files);
  file_close (file_to_be_closed->ptr);
  lock_release(&locker_for_all_files);
  list_remove(&file_to_be_closed->elem);
  palloc_free_page(file_to_be_closed);
}


unsigned 
syscall_tell(struct intr_frame *f){
  if (!is_valid_user_pointer(f->esp + 4)) syscall_exit(-1);
  int file_descriptor = *(int *)(f->esp + 4);
  uint32_t telling_file_result;
  struct opened_file_struct *file_to_be_telled = get_open_file_by_fd(file_descriptor);
  if (file_to_be_telled == NULL) return (unsigned) -1;
  lock_acquire(&locker_for_all_files);
  // off_t file_tell (struct file *file) 
  telling_file_result = file_tell(file_to_be_telled->ptr);
  lock_release(&locker_for_all_files);
  return telling_file_result;
}

void 
syscall_seek(struct intr_frame *f){
  if (!is_valid_user_pointer(f->esp + 4)) syscall_exit(-1);
  if (!is_valid_user_pointer(f->esp + 8)) syscall_exit(-1);
  int file_descriptor = *(int *)(f->esp + 4);
  uint32_t position_to_be_seeked = *(int *)(f->esp + 8);
  struct opened_file_struct *file_to_be_seeked = get_open_file_by_fd(file_descriptor);
  if (file_to_be_seeked == NULL) return;
  lock_acquire(&locker_for_all_files);
  // void file_seek (struct file *file, off_t new_pos)
  file_seek(file_to_be_seeked->ptr, position_to_be_seeked);
  lock_release(&locker_for_all_files);
}

int 
syscall_read(struct intr_frame *f){
  if (!is_valid_user_pointer(f->esp + 4)) syscall_exit(-1);
  if (!is_valid_user_pointer(f->esp + 8)) syscall_exit(-1);
  if (!is_valid_user_pointer(f->esp + 12)) syscall_exit(-1);
  int file_descriptor = *(int *)(f->esp + 4);
  void *buffer = *(void **)(f->esp + 8);
  uint32_t size_to_be_read = *(int *)(f->esp + 12);
  if (buffer == NULL || !is_valid_user_pointer(buffer))
    syscall_exit(-1);
  if (file_descriptor == STDIN_FILENO){
    for (uint32_t i = 0; i < size_to_be_read; i++){
      if (!is_valid_user_pointer(buffer + i)) syscall_exit(-1);
      lock_acquire(&locker_for_all_files);
      // uint8_t input_getc (void) 
      ((char*)buffer)[i] = input_getc();
      lock_release(&locker_for_all_files);
    }
    return size_to_be_read;
  } else {
    struct opened_file_struct *file_to_be_read = get_open_file_by_fd(file_descriptor);
    if (file_to_be_read == NULL) return -1;
    int read_result;
    lock_acquire(&locker_for_all_files);
    // off_t file_read (struct file *file, void *buffer, off_t size) 
    read_result = file_read(file_to_be_read->ptr, buffer, size_to_be_read);
    lock_release(&locker_for_all_files);
    return read_result;
  }
}

int
syscall_write(struct intr_frame *f){
  if (!is_valid_user_pointer(f->esp + 4)) syscall_exit(-1);
  if (!is_valid_user_pointer(f->esp + 8)) syscall_exit(-1);
  if (!is_valid_user_pointer(f->esp + 12)) syscall_exit(-1);
  int file_descriptor = *(int *)(f->esp + 4);
  void *buffer = *(void **)(f->esp + 8);
  uint32_t size_to_be_written = *(int *)(f->esp + 12);
  if (buffer == NULL || !is_valid_user_pointer(buffer))
    syscall_exit(-1);
  if (file_descriptor == STDOUT_FILENO){
    lock_acquire(&locker_for_all_files);
    // void putbuf (const char *buffer, size_t n) 
    putbuf(buffer, size_to_be_written);
    lock_release(&locker_for_all_files);
    return size_to_be_written;
  } else {
    struct opened_file_struct *file_to_be_written_to = get_open_file_by_fd(file_descriptor);
    if (file_to_be_written_to == NULL) return -1;
    int write_result;
    lock_acquire(&locker_for_all_files);
    // off_t file_write (struct file *file, const void *buffer, off_t size) 
    write_result = file_write(file_to_be_written_to->ptr, buffer, size_to_be_written);
    lock_release(&locker_for_all_files);
    return write_result;
  }
}

/*
  A function to get the opened file struct using 
  its file desciptor and the current thread running
*/

struct opened_file_struct* get_open_file_by_fd(int fd) {
  struct list_elem *e;
  struct thread *cur = thread_current();
  for (e = list_begin(&cur->opened_files_list); e != list_end(&cur->opened_files_list); e = list_next(e)) {
    struct opened_file_struct *ofs = list_entry(e, struct opened_file_struct, elem);
    if (ofs->fd == fd)
      return ofs;
  }
  return NULL;
}

int syscall_wait(struct intr_frame *f){
  if (!is_valid_user_pointer(f->esp + 4)) syscall_exit(-1);
  tid_t thread_id = *(int *)(f->esp + 4);
  return process_wait(thread_id);
}

tid_t syscall_exec(struct intr_frame *){
  tid_t process_id;
  if (!is_valid_user_pointer(f->esp + 4)) syscall_exit(-1);
  int* arg_ptr = (int*)f->esp + 1;
  int arg_value = *arg_ptr;
  char* the_arg = (char*)arg_value;
  if (the_arg == NULL || !is_valid_user_pointer(the_arg)) syscall_exit(-1);
  lock_acquire(&locker_for_all_files);
  process_id = process_execute(the_arg);
  lock_release(&locker_for_all_files);
  return process_id;
}

// Docker Command
// sudo docker run --platform linux/amd64 --rm -it -v "$(pwd)/PintOS-project:/root/pintos" a85bf0a348d6a4bdca899d54f162da5b76f60aaf6107808c745c3cefbaa6f644

// Commands to run the code
// pintos-mkdisk filesys.dsk --filesys-size=2
// pintos -f -q -> This is for formating

// pintos -v -p ./args-none -a args-none -- -q run args-none
// pintos -v -p ./args-many -a args-many -- -q run args-many
// pintos -v -p ./args-multiple-a args-multiple -- -q run args-multiple
// pintos -v -p ./sc-boundary-3 -a sc-boundary-3  -- -q run sc-boundary-3