#include "util.h"
#include <time.h>
#include <string.h>

// 全局变量定义
int g_debug_mode = 0;
int g_query_counter = 0;

void print_debug_info(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    fflush(stdout);
}

// 打印查询调试信息，包含时间戳、序号和域名
void print_query_debug(const char *domain)
{
    if (!g_debug_mode)
        return;

    // 获取当前时间
    time_t now;
    struct tm *timeinfo;
    char time_str[64];

    time(&now);
    timeinfo = localtime(&now);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", timeinfo);

    // 增加查询计数器
    g_query_counter++;

    // 输出调试信息
    printf("[DEBUG] Time: %s, Query #%d, Domain: %s\n",
           time_str, g_query_counter, domain);
    fflush(stdout);
}

// 获取当前高精度时间戳
void get_now(struct timeval *tv)
{
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

// 打印使用说明
void print_usage(const char *program_name)
{
    printf("Usage: %s [options]\n", program_name);
    printf("Options:\n");
    printf("  -d              Enable debug mode\n");
    printf("  <dns_server>    Specify DNS server IP (e.g., 192.168.0.1)\n");
    printf("  <config_file>   Specify configuration file path (e.g., c:\\dns-table.txt)\n");
    printf("\nExample:\n");
    printf("  %s -d 192.168.0.1 c:\\dns-table.txt\n", program_name);
    printf("  %s 8.8.8.8 dnsrelay.txt\n", program_name);
}

// 解析命令行参数
int parse_command_line(int argc, char *argv[], char **dns_server, char **config_file)
{
    *dns_server = NULL;
    *config_file = NULL;

    int arg_index = 1;

    // 检查是否有调试标志
    if (argc > 1 && strcmp(argv[1], "-d") == 0)
    {
        g_debug_mode = 1;
        arg_index = 2;
        printf("Debug mode enabled\n");
    }

    // 解析DNS服务器IP
    if (argc > arg_index)
    {
        *dns_server = argv[arg_index];
        arg_index++;
    }

    // 解析配置文件路径
    if (argc > arg_index)
    {
        *config_file = argv[arg_index];
    }

    // 如果没有提供足够的参数，使用默认值
    if (!*dns_server)
    {
        *dns_server = "10.3.9.5"; // 默认DNS服务器
    }

    if (!*config_file)
    {
        *config_file = "dnsrelay.txt"; // 默认配置文件
    }

    if (g_debug_mode)
    {
        printf("DNS Server: %s\n", *dns_server);
        printf("Config File: %s\n", *config_file);
    }

    return 0;
}