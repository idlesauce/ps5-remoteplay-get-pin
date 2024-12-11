#pragma once
#include <stdint.h>

typedef struct {
	uint64_t original_authid;
    uint8_t original_caps[16];
	uintptr_t syscall_addr;
	uintptr_t libkernel_base;
	uintptr_t errno_addr;
	int pid;
} tracer_t;

typedef struct reg reg_t;

int tracer_init(tracer_t *restrict self, int pid);
int tracer_finalize(tracer_t *restrict self);
uintptr_t tracer_call(tracer_t *restrict self, uintptr_t addr, uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f);