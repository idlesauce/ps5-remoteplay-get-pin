#pragma once

#include <stdarg.h>
#include <sys/types.h>

typedef struct notify_request
{
    char useless1[45];
    char message[3075];
} notify_request_t;

void notifyf(const char *fmt, ...);
void notifyf_printf(const char *fmt, ...);
pid_t find_pid(const char *name);
uintptr_t resolve_symbol_from_lib_for_pid(pid_t pid, const char* libname, const char* symbol);
char *base64_encode(const unsigned char *input, int length);
uint64_t get_ms_time();