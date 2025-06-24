#include "cache.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void cache_init(DNSCache *cache, int cap) {
    cache->cap = cap;
    cache->size = 0;
    cache->table = NULL;
}

DNSRecord *cache_find(DNSCache *cache, const char *domain, 
                      const uint16_t type) {
    DNSRecord *rec = NULL;
    char key[260];
    snprintf(key, sizeof(key), "%s_%u", domain, type);
    HASH_FIND_STR(cache->table, key, rec);
    if (rec) {
        // 命中则移到表尾
        print_debug_info("缓存命中: %s, type=%u, ip=%s\n", domain, type, rec->ip);
        HASH_DEL(cache->table, rec);
        HASH_ADD_STR(cache->table, domain, rec);
    } else {
        print_debug_info("缓存未命中: %s, type=%u\n", domain, type);
    }
    return rec;
}

void cache_insert(DNSCache *cache, const char *domain, 
                  const uint16_t type, const char *ip) {
    DNSRecord *rec = NULL;
    char key[260];
    snprintf(key, sizeof(key), "%s_%u", domain, type);
    HASH_FIND_STR(cache->table, key, rec);
    if (rec) {
        // 已存在则更新并移到表尾
        print_debug_info("缓存更新: %s, type=%u, ip=%s -> %s\n", domain, type, rec->ip, ip);
        strncpy(rec->ip, ip, sizeof(rec->ip)-1);
        rec->ip[sizeof(rec->ip)-1] = '\0';
        HASH_DEL(cache->table, rec);
        HASH_ADD_STR(cache->table, domain, rec);
        return;
    }
    // 超出容量则淘汰最旧
    if (cache->size >= cache->cap) {
        DNSRecord *oldest = cache->table;
        print_debug_info("缓存淘汰: %s, type=%u, ip=%s\n", oldest->domain, oldest->type, oldest->ip);
        HASH_DEL(cache->table, oldest);
        free(oldest);
        cache->size--;
    }
    rec = (DNSRecord*)malloc(sizeof(DNSRecord));
    strncpy(rec->domain, key, sizeof(rec->domain)-1);
    rec->domain[sizeof(rec->domain)-1] = '\0';
    strncpy(rec->ip, ip, sizeof(rec->ip)-1);
    rec->ip[sizeof(rec->ip)-1] = '\0';
    rec->type = type;
    print_debug_info("缓存新增: %s, type=%u, ip=%s\n", domain, type, ip);
    HASH_ADD_STR(cache->table, domain, rec);
    cache->size++;
}

void cache_free(DNSCache *cache) {
    DNSRecord *cur, *tmp;
    HASH_ITER(hh, cache->table, cur, tmp) {
        HASH_DEL(cache->table, cur);
        free(cur);
    }
    cache->table = NULL;
    cache->size = 0;
}
