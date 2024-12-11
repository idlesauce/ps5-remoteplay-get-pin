#include "utils.h"

#include <stdio.h>
#include <sys/sysctl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <time.h>

#include <ps5/kernel.h>

int sceKernelSendNotificationRequest(int, notify_request_t *, size_t, int);


void notifyf(const char *fmt, ...)
{
    notify_request_t req = {0};
    va_list args;
    va_start(args, fmt);
    vsnprintf(req.message, sizeof(req.message), fmt, args);
    va_end(args);
    sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
}

void notifyf_printf(const char *fmt, ...)
{
    notify_request_t req = {0};
    va_list args;
    va_start(args, fmt);
    vsnprintf(req.message, sizeof(req.message), fmt, args);
    va_end(args);
    sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);

    printf("%s\n", req.message);
}


// https://github.com/ps5-payload-dev/ftpsrv/blob/27984bb0ad2fbd88d0e442f46773c7dc3d95361d/main.c#L358
pid_t find_pid(const char *name)
{
    int mib[4] = {1, 14, 8, 0};
    pid_t mypid = getpid();
    pid_t pid = -1;
    size_t buf_size;
    uint8_t *buf;

    if (sysctl(mib, 4, 0, &buf_size, 0, 0))
    {
        return -1;
    }

    if (!(buf = malloc(buf_size)))
    {
        return -1;
    }

    if (sysctl(mib, 4, buf, &buf_size, 0, 0))
    {
        free(buf);
        return -1;
    }

    for (uint8_t *ptr = buf; ptr < (buf + buf_size);)
    {
        int ki_structsize = *(int *)ptr;
        pid_t ki_pid = *(pid_t *)&ptr[72];
        char *ki_tdname = (char *)&ptr[447];

        ptr += ki_structsize;
        if (!strcmp(name, ki_tdname) && ki_pid != mypid)
        {
            pid = ki_pid;
        }
    }

    free(buf);

    return pid;
}

uintptr_t resolve_symbol_from_lib_for_pid(pid_t pid, const char *libname, const char *symbol)
{
    uint32_t handle = 0;
    if (kernel_dynlib_handle(pid, libname, &handle) || !handle)
    {
        return 0;
    }

    return kernel_dynlib_dlsym(pid, handle, symbol);
}

static const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char *base64_encode(const unsigned char *input, int length)
{
    int output_length = 4 * ((length + 2) / 3);
    char *output = (char *)malloc(output_length + 1); // +1 for the null terminator
    if (output == NULL)
    {
        return NULL;
    }

    int i, j;
    for (i = 0, j = 0; i < length;)
    {
        uint32_t octet_a = i < length ? input[i++] : 0;
        uint32_t octet_b = i < length ? input[i++] : 0;
        uint32_t octet_c = i < length ? input[i++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        output[j++] = base64_table[(triple >> 3 * 6) & 0x3F];
        output[j++] = base64_table[(triple >> 2 * 6) & 0x3F];
        output[j++] = base64_table[(triple >> 1 * 6) & 0x3F];
        output[j++] = base64_table[(triple >> 0 * 6) & 0x3F];
    }

    for (int k = 0; k < (3 - length % 3) % 3; k++)
    {
        output[output_length - 1 - k] = '=';
    }

    output[output_length] = '\0';
    return output;
}

uint64_t get_ms_time()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}