#ifndef DNS_CACHE_H
#define DNS_CACHE_H

#include "uthash.h"
#include "util.h"
#include <stdint.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#include <sys/time.h>
#endif

// 缓存条目结构
typedef struct cache_entry
{
    char domain[256];            // 域名（键）
    char ip[46];                 // IP地址 (IPv4最大15字符, IPv6最大45字符)
    uint16_t qtype;              // 查询类型（A、AAAA等）
    uint32_t ttl;                // 原始TTL值（秒）
    struct timeval created_time; // 创建时间
    struct timeval expire_time;  // 过期时间
    UT_hash_handle hh;           // uthash处理句柄
} CacheEntry;

// 缓存统计信息
typedef struct cache_stats
{
    uint64_t hits;         // 缓存命中次数
    uint64_t misses;       // 缓存未命中次数
    uint64_t expired;      // 过期条目数
    uint64_t evicted;      // 被驱逐条目数
    uint32_t current_size; // 当前缓存大小
    uint32_t max_size;     // 最大缓存大小
} CacheStats;

// 缓存管理器
typedef struct dns_cache
{
    CacheEntry *entries;  // 缓存条目哈希表
    CacheStats stats;     // 统计信息
    uint32_t max_entries; // 最大条目数
    uint32_t default_ttl; // 默认TTL（当上游响应没有TTL时使用）
    uint32_t min_ttl;     // 最小TTL
    uint32_t max_ttl;     // 最大TTL
} DNSCache;

// 缓存初始化和清理
DNSCache *cache_create(uint32_t max_entries, uint32_t default_ttl,
                       uint32_t min_ttl, uint32_t max_ttl);
void cache_destroy(DNSCache *cache);

// 缓存操作
int cache_put(DNSCache *cache, const char *domain, uint16_t qtype,
              const char *ip, uint32_t ttl);
CacheEntry *cache_get(DNSCache *cache, const char *domain, uint16_t qtype);
int cache_remove(DNSCache *cache, const char *domain, uint16_t qtype);

// 缓存维护
void cache_cleanup_expired(DNSCache *cache);
void cache_evict_lru(DNSCache *cache);
int cache_is_expired(const CacheEntry *entry);
uint32_t cache_get_remaining_ttl(const CacheEntry *entry);

// 缓存统计
void cache_print_stats(const DNSCache *cache);
double cache_hit_rate(const DNSCache *cache);

// 工具函数
void cache_key_generate(char *key, const char *domain, uint16_t qtype);
void timeval_add_seconds(struct timeval *tv, uint32_t seconds);

#endif /* DNS_CACHE_H */
