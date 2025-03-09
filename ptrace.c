// https://github.com/astrelsky/HEN-V/blob/8d45c365e592705fa23be72443df71ba471b7ee0/spawner/source/tracer.c
// https://github.com/ps5-payload-dev/websrv/blob/7734267a1e771f17d23838ce9bcd66f51c168297/src/ps5/pt.c

#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/sysctl.h>

#include <ps5/kernel.h>
#include <ps5/mdbg.h>

#include "ptrace.h"

int tracer_init(tracer_t *restrict self, int pid)
{
    memset(self, 0, sizeof(tracer_t));

    uint8_t privcaps[16] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    pid_t mypid = getpid();
    if (mypid == pid)
    {
        return -1;
    }

    uint64_t og_authid = kernel_get_ucred_authid(mypid);
    if (og_authid == 0)
    {
        return -1;
    }

    uint8_t og_caps[16] = {0};
    if (kernel_get_ucred_caps(mypid, og_caps))
    {
        return -1;
    }

    if (kernel_set_ucred_authid(mypid, 0x4800000000010003l))
    {
        return -1;
    }

    if (kernel_set_ucred_caps(mypid, privcaps))
    {
        kernel_set_ucred_authid(mypid, og_authid);
        return -1;
    }

    if ((int)syscall(SYS_ptrace, PT_ATTACH, pid, 0, 0) < 0)
    {
        kernel_set_ucred_authid(mypid, og_authid);
        kernel_set_ucred_caps(mypid, og_caps);
        return -1;
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0)
    {
        return -1;
    }

    self->pid = pid;
    self->original_authid = og_authid;
    memcpy(self->original_caps, og_caps, sizeof(og_caps));

    return 0;
}

int tracer_finalize(tracer_t *restrict self)
{
    if (self->pid == 0)
    {
        return -1;
    }

    if ((int)syscall(SYS_ptrace, PT_DETACH, self->pid, 0, 0))
    {
        return -1;
    }

    kernel_set_ucred_authid(getpid(), self->original_authid);
    kernel_set_ucred_caps(getpid(), self->original_caps);

    self->pid = 0;

    return 0;
}

static void set_args(reg_t *restrict regs, uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f)
{
    regs->r_rdi = (register_t)a;
    regs->r_rsi = (register_t)b;
    regs->r_rdx = (register_t)c;
    regs->r_rcx = (register_t)d;
    regs->r_r8 = (register_t)e;
    regs->r_r9 = (register_t)f;
}

#define LIBKERNEL_HANDLE 0x2001

uintptr_t tracer_call(tracer_t *restrict self, uintptr_t addr, uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f)
{
    if (addr == 0)
    {
        puts("invalid address");
        errno = EINVAL;
        return (uintptr_t)-1L;
    }

    reg_t jmp;
    if ((int)syscall(SYS_ptrace, PT_GETREGS, self->pid, (caddr_t)&jmp, 0) < 0)
    {
        puts("failed to get registers");
        return (uintptr_t)-1L;
    }

    const reg_t backup = jmp;
    
    jmp.r_rip = (register_t)addr;
    set_args(&jmp, a, b, c, d, e, f);

    if (self->libkernel_base == 0)
    {
        self->libkernel_base = kernel_dynlib_mapbase_addr(self->pid, LIBKERNEL_HANDLE);
        if (self->libkernel_base == 0)
        {
            puts("failed to get libkernel base for traced proc");
            return -1;
        }
    }

    jmp.r_rsp = (register_t)(jmp.r_rsp - sizeof(uintptr_t));

    if ((int)syscall(SYS_ptrace, PT_SETREGS, self->pid, (caddr_t)&jmp, 0) < 0)
    {
        puts("failed to set registers");
        return -1;
    }

    // set the return address to the `INT3` at the start of libkernel
    mdbg_copyin(self->pid, &self->libkernel_base, jmp.r_rsp, sizeof(self->libkernel_base));

    // call the function
    if ((int)syscall(SYS_ptrace, PT_CONTINUE, self->pid, (caddr_t)1, 0) < 0)
    {
        puts("failed to continue");
        return -1;
    }

    int state = 0;
    if (waitpid(self->pid, &state, 0) < 0)
    {
        puts("failed to wait");
        return -1;
    }

    if (!WIFSTOPPED(state))
    {
        puts("process not stopped");
        return -1;
    }

    if (WSTOPSIG(state) != SIGTRAP)
    {
        printf("process received signal %d but SIGTRAP was expected\n", WSTOPSIG(state));
        return -1;
    }

    if ((int)syscall(SYS_ptrace, PT_GETREGS, self->pid, (caddr_t)&jmp, 0) < 0)
    {
        puts("failed to get registers");
        return -1;
    }

    // restore registers
    if ((int)syscall(SYS_ptrace, PT_SETREGS, self->pid, (caddr_t)&backup, 0) < 0)
    {
        perror("tracer_start_call set registers failed");
        return -1;
    }

    return jmp.r_rax;
}
