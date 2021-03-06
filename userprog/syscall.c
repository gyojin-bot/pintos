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
#include "lib/kernel/console.h"
#include "filesys/off_t.h"
// #include "lib/user/syscall.h"
// #include "threads/mmu.h"
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
	//  

    // uint64_t* syscall_num = f->R.rsp;
    // void* esp = f->rsp;
    //hex_dump(f->rsp, f->rsp, USER_STACK - f->rsp, 1);
    // uint64_t argv = f->R.rsi;
    // uint64_t count = f->R.rdi;
    
    // int syscall_num = f->R.rax;
    // printf("syscll num :: %d\n\n", syscall_num);
    switch (f->R.rax)
    {
    case SYS_HALT:                   /* Halt the operating system. */
        halt();
        break;
    
    case SYS_EXIT:                   /* Terminate this process. */
        exit(f->R.rdi);
        break;

    case SYS_FORK:                   /* Clone current process. */
        f->R.rax = Fork(f->R.rdi, f);
        break;

    case SYS_EXEC:                   /* Switch current process. */
        f->R.rax = exec(f->R.rdi);
        break;
    
    case SYS_WAIT:                   /* Wait for a child process to die. */
        f->R.rax = wait(f->R.rdi);
        break;

    case SYS_CREATE:                 /* Create a file. */
        check_address(f->R.rdi);
        f->R.rax = create(f->R.rdi, f->R.rsi);
        break;

    case SYS_REMOVE:                 /* Delete a file. */
        f->R.rax = remove(f->R.rdi);
        break;
    
    case SYS_OPEN:                   /* Open a file. */
        f->R.rax = open(f->R.rdi);
        break;

    case SYS_FILESIZE:               /* Obtain a file's size. */
        f->R.rax = filesize(f->R.rdi);
        break;
    
    case SYS_READ:                   /* Read from a file. */
        f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
        break;
    
    case SYS_WRITE:                  /* Write to a file. */
        f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
        //f->R.rax = write(*(int*)f->R.rdi, f->R.rsi, *(int64_t*)f->R.rdx);
        break;

    case SYS_SEEK:                   /* Change position in a file. */
        seek(f->R.rdi, f->R.rsi);
        break;
    
    case SYS_TELL:                   /* Report current position in a file. */
        f->R.rax = tell(f->R.rdi);
        break;

    case SYS_CLOSE:                  /* Close a file. */
        close(f->R.rdi);
        break;
    
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
        exit(-1);
}
// void get_argument(void *rax, int *arg , int count)
// {
// /* 유저 스택에 저장된 인자값들을 커널로 저장 */
// /* 인자가 저장된 위치가 유저영역인지 확인 */
    
//     int i = 0;
//     while (i < count){
//         check_address(rax + 8);
//         rax = rax + 8;
//         arg[i] = rax;
//         ++i;
//     }
// }

void halt (void)
{
    /* shutdown_power_off()를사용하여pintos 종료*/
    power_off();
}

void exit (int status)
{
    /* 실행중인스레드구조체를가져옴*/
    /* 프로세스종료메시지출력,
    출력양식: “프로세스이름: exit(종료상태)” */
    // if(thread_current()->parent)
    printf("%s: exit(%d)\n", thread_name(), status);
    thread_current()->exit_status = status;
    thread_exit();
    /* 스레드종료*/
}

pid_t Fork (const char *thread_name, struct intr_frame* f){
	return process_fork(thread_name, f);
}

int exec (const char *file)
{
    // return wait(process_create_initd(file));
    // int child_pid = process_exec(file);
    // struct thread *child = get_child_process(child_pid);
    // sema_down(&child->load);
    // return child_pid;
    return process_exec(file);

    // return child->load_success;
        // return pid;
    // thread_exit();
    // return process_exec(file);
    
    // if(exit_status != -1)
    //     return exit_status;
}

int wait (tid_t pid)
{
    return process_wait(pid);
}

bool create(const char *file , unsigned initial_size)
{
    /* 파일이름과크기에해당하는파일생성*/
    if (file == NULL || file ==""){
        exit(-1);
    }
    // bool success = filesys_create(file, initial_size);
    // /* 파일생성성공시true 반환, 실패시false 반환*/
    // if (!success)
    //     return false;
    else
        return filesys_create(file, initial_size);
}

bool remove(const char *file)
{
    if (file == NULL || file =="")
        return false;
    /* 파일이름에해당하는파일을제거*/
    // filesys_remove(file);
    /* 파일제거성공시true 반환, 실패시false 반환*/
    // if (file == NULL)
    //     return true;
    return filesys_remove(file);;
}

int write(int fd, const void *buffer, unsigned size)
{
    lock_acquire(&filesys_lock);

    if(fd == 1){
        putbuf(buffer, size);
        lock_release(&filesys_lock);
        return size;
    }
    struct file *f = thread_current()->fd_table[fd];

    if(f==NULL){
        lock_release(&filesys_lock);
        return 0;
    }
        
    // file_deny_write(thread_current()->fd_table[fd]);
    int result =  file_write(f, buffer, size);
    lock_release(&filesys_lock);
    return result;
}

int open(const char *file){
    if (file == NULL || file =="")
        return -1;
    // lock_acquire(&filesys_lock);
    struct file *f = filesys_open(file);
    if (f == NULL)
        return -1;
    // file_deny_write(f);
    // if (strcmp(thread_current()->name, file) == 0)
    //     file_deny_write(f);
    // for (int i = 2; i < thread_current()->parent_fd; ++i){
    //     if (strcmp(thread_name(), file) == 0)
    //         return i;
            // file_deny_write(f);
    // }
    int result = process_add_file(f);
    // lock_release(&filesys_lock);
    return result;
}

int filesize(int fd){
    struct file *f = thread_current()->fd_table[fd];
    if (f == NULL)
        return -1;
    int size;
    size = file_length(f);
    return size;
}

int read(int fd, void *buffer, unsigned size){
    lock_acquire(&filesys_lock);
    if(fd == 0){
        int i = 0;
        while(i<size){
            *(char*)buffer = input_getc();
            buffer = buffer + 1;
            i++;
        }
        lock_release(&filesys_lock);
        return size;
    }
    struct file *f = thread_current()->fd_table[fd];
    
    if(f==NULL){
        lock_release(&filesys_lock);
        return -1;
    }
    size = file_read(f, buffer, size);
    lock_release(&filesys_lock);
    return size;
}

void seek(int fd, unsigned position){
    struct file *f = thread_current()->fd_table[fd];

    file_seek(f, position);    
}

unsigned tell(int fd){
    struct file *f = thread_current()->fd_table[fd];
    return file_tell(f);
}

void close(int fd){
    process_close_file(fd);
}