#include "table.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 调试信息输出函数声明
void print_debug_info(const char* format, ...);

// 加载DNS表，将dnsrelay.txt中的域名-IP映射读入哈希表
int load_dns_table(const char* filename, DNSRecord** table) {
    FILE* fp;
    char line[512];
    char ip[16], domain[256];
    int count = 0;
    // 打开配置文件
    fp = fopen(filename, "r");
    if (!fp) {
        print_debug_info("无法打开配置文件 %s\n", filename);
        return -1;
    }
    *table = NULL; // 初始化哈希表
    // 逐行读取配置文件
    while (fgets(line, sizeof(line), fp)) {
        DNSRecord* record;
        // 解析一行，格式: IP 域名
        if (sscanf(line, "%s %s", ip, domain) != 2) {
            continue;
        }
        // 分配新节点
        record = (DNSRecord*)malloc(sizeof(DNSRecord));
        if (!record) {
            continue;
        }
        // 拷贝IP和域名
        strncpy(record->ip, ip, sizeof(record->ip)-1);
        record->ip[sizeof(record->ip)-1] = '\0';
        strncpy(record->domain, domain, sizeof(record->domain)-1);
        record->domain[sizeof(record->domain)-1] = '\0';
        // 加入哈希表
        HASH_ADD_STR(*table, domain, record);
        count++;
        print_debug_info("加载记录: %s -> %s\n", domain, ip);
    }
    fclose(fp);
    print_debug_info("总共加载 %d 条记录\n", count);
    return count;
}

// 释放DNS表，释放所有节点内存
void free_dns_table(DNSRecord* table) {
    DNSRecord *current, *tmp;
    HASH_ITER(hh, table, current, tmp) {
        HASH_DEL(table, current);
        free(current);
    }
}

void free_relay_table(RelayEntry* table) {
    RelayEntry *current, *tmp;
    HASH_ITER(hh, table, current, tmp) {
        HASH_DEL(table, current);
        free(current);
    }
}
