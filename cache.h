#ifndef CACHE_H
#define CACHE_H
#include "table.h"

// LRU缓存结构体，维护DNS缓存表、容量和当前大小
typedef struct {
    int cap;                // 最大缓存容量
    int size;               // 当前缓存数量
    DNSRecord *table;       // LRU缓存表头（哈希+链表）
} DNSCache;

// 初始化缓存
void cache_init(DNSCache *cache, int cap);
// 查询缓存，命中则移动到表尾
DNSRecord *cache_find(DNSCache *cache, const char *domain);
// 插入缓存，自动淘汰最旧
void cache_insert(DNSCache *cache, const char *domain, const char *ip);
// 释放缓存
void cache_free(DNSCache *cache);
#endif /* CACHE_H */