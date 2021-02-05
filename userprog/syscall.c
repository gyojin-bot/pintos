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

    // uint64_t syscall_num = f->rip;
    // void* esp = f->rsp;
    msg("rip :: %p\n", f->rip);
    msg("rsp :: %p\n", f->rsp);
    hex_dump(f->rsp, (void *)(f->rsp), USER_STACK - f->rsp, 1);
    // uint64_t argv = f->R.rsi;
    // uint64_t count = f->R.rdi;
    // check_address(&argv);

    // int syscall_num = f->R.rax;
    switch (1)
    {
    case SYS_HALT:                   /* Halt the operating system. */
        halt();
        break;
    
    case SYS_EXIT:                   /* Terminate this process. */
        break;
    
    case SYS_FORK:                   /* Clone current process. */
        break;

    case SYS_EXEC:                   /* Switch current process. */
        break;
    
    case SYS_WAIT:                   /* Wait for a child process to die. */
        break;

    case SYS_CREATE:                 /* Create a file. */
        break;

    case SYS_REMOVE:                 /* Delete a file. */
        break;
    
    case SYS_OPEN:                   /* Open a file. */
        break;

    case SYS_FILESIZE:               /* Obtain a file's size. */
        break;
    
    case SYS_READ:                   /* Read from a file. */
        break;
    
    case SYS_WRITE:                  /* Write to a file. */
        write();
        break;

    case SYS_SEEK:                   /* Change position in a file. */
        break;
    
    case SYS_TELL:                   /* Report current position in a file. */
        break;

    case SYS_CLOSE:                  /* Close a file. */
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
    {
        exit(-1);
    }
}
// void get_argument(void *esp)//, int *arg , int count)
// {
// /* 유저 스택에 저장된 인자값들을 커널로 저장 */
// /* 인자가 저장된 위치가 유저영역인지 확인 */
//     check_address(&esp);
//     while (esp < USER_STACK){
//         long a = *(long*)esp;
//         printf("%p\n", esp);
//         printf("%d\n", *esp);
//         esp = esp + 8;
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
    struct thread *curr = thread_current();
    /* 프로세스종료메시지출력,
    출력양식: “프로세스이름: exit(종료상태)” */
    msg("프로세스이름: %s exit(%d)", curr->name, status);
    /* 스레드종료*/
    thread_exit();
}

bool create(const char *file , unsigned initial_size)
{
    /* 파일이름과크기에해당하는파일생성*/
    // file = filesys_create(file, initial_size);
    /* 파일생성성공시true 반환, 실패시false 반환*/
    if (file == NULL)
        return false;
    return true;
}

bool remove(const char *file)
{
    /* 파일이름에해당하는파일을제거*/
    palloc_free_page(file);
    /* 파일제거성공시true 반환, 실패시false 반환*/
    if (file == NULL)
        return true;
    return false;
}

int write(int fd, const void *buffer, unsigned size)
{
    file_write(fd, &buffer, size);
}