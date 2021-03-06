#include <stdbool.h>
#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
typedef int pid_t;
#include "threads/synch.h"
// #include "lib/user/syscall.h"
void syscall_init (void);

void check_address(void *addr);
void get_argument(void *esp, int *arg, int count);

void halt (void);
void exit (int status);
// pid_t Fork(const char *thread_name, struct intr_frame* f);
int exec (const char *file);
int wait (tid_t);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned length);
int write (int fd, const void *buffer, unsigned length);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);

int dup2(int oldfd, int newfd);
struct lock filesys_lock;

#endif /* userprog/syscall.h */
