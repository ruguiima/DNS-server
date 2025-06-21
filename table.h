#ifndef DNSRELAY_H
#define DNSRELAY_H

#include "uthash.h"
#include <stdint.h>

// DNS记录结构，用于哈希表存储
typedef struct dns_record {
    char domain[256];     // 域名(键)
    char ip[16];         // IP地址字符串
    UT_hash_handle hh;   // uthash处理句柄
} DNSRecord;

int load_dns_table(const char* filename, DNSRecord** table);
void free_dns_table(DNSRecord* table);
#endif /* DNSRELAY_H */
