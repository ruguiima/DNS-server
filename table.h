#ifndef DNSRELAY_H
#define DNSRELAY_H

#include "uthash.h"
#include <time.h>
#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif
#include <stdint.h>

// DNS记录结构，用于哈希表存储
typedef struct dns_record
{
    char domain[256];  // 域名(键)
    char ip[46];       // IP地址字符串 (支持IPv4和IPv6)
    UT_hash_handle hh; // uthash处理句柄
} DNSRecord;

// ID映射表结构定义
typedef struct relay_entry
{
    uint16_t upstream_id;           // 转发到上游的新ID
    uint16_t client_id;             // 客户端原始ID
    struct sockaddr_in client_addr; // 客户端地址
    uint8_t query[512];             // 查询数据缓冲区
    int question_len;               // 查询数据长度
    struct timeval timestamp;       // 时间戳，用于超时处理
    UT_hash_handle hh;              // uthash处理句柄
} RelayEntry;

int load_dns_table(const char *filename, DNSRecord **table);
void free_dns_table(DNSRecord *table);
void free_relay_table(RelayEntry *table);
#endif /* DNSRELAY_H */
