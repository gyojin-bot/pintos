#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

#include "threads/init.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
// #include "threads/mmu.h"
// #include "lib/user/syscall.h"
// #include "lib/syscall-nr.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);
    lock_init(&filesys_lock);
	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	printf ("system call!\n");

    // uint64_t* syscall_num = f->R.rsp;
    // void* esp = f->rsp;
    printf("rax : %d\n", f->R.rax);
    printf("rdi : %d\n", f->R.rdi);
    printf("rsi : %p\n", f->R.rsi);
    printf("rdx : %d\n", f->R.rdx);
    printf("r10 : %d\n", f->R.r10);
    printf("r8 : %d\n", f->R.r8);
    printf("r9 : %d\n", f->R.r9);
    //hex_dump(f->rsp, (void *)(f->rsp), USER_STACK - f->rsp, 1);
    // uint64_t argv = f->R.rsi;
    // uint64_t count = f->R.rdi;
    check_address(f->R.rax);
    char *arg[6];

    int syscall_num = f->R.rax;
    printf("syscll num :: %d\n\n", syscall_num);
    switch (syscall_num)
    {
    // case SYS_HALT:                   /* Halt the operating system. */
    //     halt();
    //     break;
    
    // case SYS_EXIT:                   /* Terminate this process. */
    //     get_argument(f->R.rax, arg, 1);
    //     exit(arg[0]);
    //     break;

    // case SYS_FORK:                   /* Clone current process. */
    //     get_argument(f->R.rax, arg, 1);
    //     // fork(arg[0]);
    //     break;

    case SYS_EXEC:                   /* Switch current process. */
        get_argument(&f->R.rax, arg, 1);
        f->R.rax = exec(*(const char*)arg[0]);
        break;
    
    // case SYS_WAIT:                   /* Wait for a child process to die. */
    //     get_argument(f->R.rax, arg, 1);
    //     // f->R.rax = wait(*(pid_t*)arg[0]);
    //     break;

    // case SYS_CREATE:                 /* Create a file. */
    //     break;

    // case SYS_REMOVE:                 /* Delete a file. */
    //     break;
    
    // case SYS_OPEN:                   /* Open a file. */
    //     break;

    // case SYS_FILESIZE:               /* Obtain a file's size. */
    //     break;
    
    // case SYS_READ:                   /* Read from a file. */
    //     break;
    
    case SYS_WRITE:                  /* Write to a file. */
        get_argument(f->R.rax, arg, 3);
        f->R.rax = write(*(int*)arg[0], arg[1], *(unsigned *) arg[2]);
        write(*(int64_t*)f->R.rdi, f->R.rsi, *(int64_t*)f->R.rdx);
        break;

    // case SYS_SEEK:                   /* Change position in a file. */
    //     break;
    
    // case SYS_TELL:                   /* Report current position in a file. */
    //     break;

    // case SYS_CLOSE:                  /* Close a file. */
    //     break;
    
    default:
        thread_exit ();
        break;
    }
}

void check_address(void *addr)
{
/* 포인터가 가리키는 주소가 유저영역의 주소인지 확인 */
/* 잘못된 접근일 경우 프로세스 종료 */
    if(!is_user_vaddr(addr))
    {
        process_exit(-1);
    }
}
void get_argument(void *rsp, int *arg , int count)
{
/* 유저 스택에 저장된 인자값들을 커널로 저장 */
/* 인자가 저장된 위치가 유저영역인지 확인 */
    
    int i = 0;
    while (i < count){
        check_address(rsp + 8);
        rsp = rsp + 8;
        arg[i] = rsp;
        ++i;
    }
}

// void halt (void)
// {
//     /* shutdown_power_off()를사용하여pintos 종료*/
//     power_off();
// }

void exit (int status)
{
    /* 실행중인스레드구조체를가져옴*/
    struct thread *curr = thread_current();
    /* 프로세스종료메시지출력,
    출력양식: “프로세스이름: exit(종료상태)” */
    printf("프로세스이름: %s exit(%d)", curr->name, status);
    thread_exit();
    /* 스레드종료*/
}

// // pid_t
// // fork (const char *thread_name){
// //     pml4_for_each (uint64_t *pml4, pte_for_each_func *func, void *aux);
// // 	return (pid_t) syscall1 (SYS_FORK, thread_name);
// // }

int exec (const char *file)
{
    int pid = process_create_initd(file);
    struct thread *child = get_child_process(pid);
    
    sema_down(&child->load);
    if(!child->load_success)
        return -1;

    return pid;
}

int wait (tid_t pid)
{
    return process_wait(pid);
}

// bool create(const char *file , unsigned initial_size)
// {
//     /* 파일이름과크기에해당하는파일생성*/
//     file = filesys_create(file, initial_size);
//     /* 파일생성성공시true 반환, 실패시false 반환*/
//     if (file == NULL)
//         return false;
//     return true;
// }

// bool remove(const char *file)
// {
//     /* 파일이름에해당하는파일을제거*/
//     palloc_free_page(file);
//     /* 파일제거성공시true 반환, 실패시false 반환*/
//     if (file == NULL)
//         return true;
//     return false;
// }

int write(int fd, const void *buffer, unsigned size)
{
    lock_acquire(&filesys_lock);
    
    struct file *f = process_get_file(fd);
    int i = 0;
    if(f==NULL){
        lock_release(&filesys_lock);
        return 0;
    }
    if(fd == 1){
        putbuf(buffer, size);
        lock_release(&filesys_lock);
        return size;
    }
    else{
        file_write(f, buffer, size);
        lock_release(&filesys_lock);
        return file_read(f, buffer, size);
    }
}

int open(const char *file){
    struct file *f = filesys_open(file);
    if (f == NULL)
        return -1;
    return process_add_file(f);
}

int filesize(int fd){
    struct file *f = process_get_file(fd);
    int size;
    if (f == NULL)
        return -1;
    size = file_length(f);
    return size;
}

int read(int fd, void *buffer, unsigned size){
    lock_acquire(&filesys_lock);
    struct file *f = process_get_file(fd);
    int i = 0;
    if(f==NULL){
        lock_release(&filesys_lock);
        return -1;
    }
    if(fd == 0){
        while(i<size){
            *(char*)buffer = input_getc();
            buffer = buffer + 1;
            i++;
        }
        lock_release(&filesys_lock);
        return size;
    }
    else{
        lock_release(&filesys_lock);
        return file_read(f, buffer, size);
    }
}

void seek(int fd, unsigned position){
    struct file *f = process_get_file(fd);
    file_seek(f, position);    
}

unsigned tell(int fd){
    struct file *f = process_get_file(fd);
    return file_tell(f);
}

void close(int fd){
    process_close_file(fd);
}