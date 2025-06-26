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

void print_debug_info(const char *format, ...);
void print_query_debug(const char *domain);
void get_now(struct timeval *tv);
void print_usage(const char *program_name);
int parse_command_line(int argc, char *argv[], char *dns_server, size_t dns_server_len, char *config_file,
                       size_t config_file_len);

#endif // UTIL_H