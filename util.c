#include "util.h"


void print_debug_info(const char* format, ...) {
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    fflush(stdout);
}

// 获取当前高精度时间戳
void get_now(struct timeval* tv) {
#ifdef _WIN32
    FILETIME ft;
    ULARGE_INTEGER uli;
    GetSystemTimeAsFileTime(&ft);
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    // Windows FILETIME是100纳秒为单位，从1601年1月1日
    // 转换为UNIX时间戳（秒+微秒）
    uint64_t t = (uli.QuadPart - 116444736000000000ULL) / 10; // 微秒
    tv->tv_sec = (long)(t / 1000000);
    tv->tv_usec = (long)(t % 1000000);
#else
    gettimeofday(tv, NULL);
#endif
}