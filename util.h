#ifndef UTIL_H
#define UTIL_H

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/time.h>
#endif

void print_debug_info(const char* format, ...);
void get_now(struct timeval* tv);

#endif  // UTIL_H