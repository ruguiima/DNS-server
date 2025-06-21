#include <stdio.h>
#include <stdarg.h>

void print_debug_info(const char* format, ...) {
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    fflush(stdout);
}