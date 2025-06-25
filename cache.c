#include "cache.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"


/**
 * 创建DNS缓存管理器
 * @param max_entries 最大缓存条目数
 * @param default_ttl 默认TTL（秒）
 * @param min_ttl 最小TTL（秒）
 * @param max_ttl 最大TTL（秒）
 * @return 缓存管理器指针，失败返回NULL
 */
DNSCache *cache_create(uint32_t max_entries) {
    DNSCache *cache = malloc(sizeof(DNSCache));
    if (!cache) {
        print_debug_info("缓存创建失败：内存分配错误\n");
        return NULL;
    }

    memset(cache, 0, sizeof(DNSCache));
    cache->entries = NULL;
    cache->stats.max_size = max_entries;

    print_debug_info("DNS缓存已创建：最大条目=%u", max_entries);
    return cache;
}

// 销毁DNS缓存管理器
void cache_destroy(DNSCache *cache) {
    if (!cache) return;

    CacheEntry *entry, *tmp;
    HASH_ITER(hh, cache->entries, entry, tmp) {
        HASH_DEL(cache->entries, entry);
        free(entry);
    }

    print_debug_info("DNS缓存已销毁：命中率=%.2f%%, 总命中=%llu, 总未命中=%llu\n", cache_hit_rate(cache),
                     cache->stats.hits, cache->stats.misses);
    free(cache);
}

// 生成缓存键（域名+查询类型）
static inline void cache_key_generate(char *key, const char *domain, uint16_t qtype) { 
    snprintf(key, 270, "%s#%u", domain, qtype); 
}

//获取缓存条目剩余TTL
uint32_t cache_get_remaining_ttl(const CacheEntry *entry) {
    struct timeval now;
    get_now(&now);
    return (uint32_t)(entry->expire_time.tv_sec - now.tv_sec);
}

/**
 * 向缓存添加条目
 * @param cache 缓存管理器
 * @param domain 域名
 * @param qtype 查询类型
 * @param ip IP地址
 * @param ttl TTL值
 * @return 0成功，-1失败
 */
int cache_put(DNSCache *cache, const char *domain, uint16_t qtype, const char *ip, uint32_t ttl) {
    if (!cache || !domain || !ip) {
        return -1;
    }

    char key[270];
    cache_key_generate(key, domain, qtype);

    CacheEntry *existing;
    HASH_FIND_STR(cache->entries, key, existing);

    if (existing) {
        // 先删除再插入，保持LRU顺序
        HASH_DEL(cache->entries, existing);
        strncpy(existing->ip, ip, sizeof(existing->ip) - 1);
        existing->ip[sizeof(existing->ip) - 1] = '\0';
        existing->ttl = ttl;
        get_now(&existing->created_time);
        existing->expire_time.tv_sec = existing->created_time.tv_sec + ttl;
        HASH_ADD_STR(cache->entries, key, existing);

        print_debug_info("缓存更新：%s (%u) -> %s, TTL=%u秒\n", domain, qtype, ip, ttl);
        return 0;
    }

    // 检查缓存大小限制
    if (cache->stats.current_size >= cache->stats.max_size) {
            // 直接淘汰哈希表头部（最久未使用）
            CacheEntry *oldest = cache->entries;
            if (oldest) {
                print_debug_info("LRU驱逐：%s\n", oldest->key);
                HASH_DEL(cache->entries, oldest);
                free(oldest);
                cache->stats.current_size--;
                cache->stats.evicted++;
            }
    }

    // 创建新条目
    CacheEntry *entry = malloc(sizeof(CacheEntry));
    if (!entry) {
        print_debug_info("缓存添加失败：内存分配错误\n");
        return -1;
    }

    strncpy(entry->key, key, sizeof(entry->key) - 1);
    entry->key[sizeof(entry->key) - 1] = '\0';
    strncpy(entry->ip, ip, sizeof(entry->ip) - 1);
    entry->ip[sizeof(entry->ip) - 1] = '\0';
    entry->qtype = qtype;
    entry->ttl = ttl;

    get_now(&entry->created_time);
    entry->expire_time.tv_sec = entry->created_time.tv_sec + ttl;

    HASH_ADD_STR(cache->entries, key, entry);
    cache->stats.current_size++;

    print_debug_info("缓存添加：%s (%u) -> %s, TTL=%u秒\n", domain, qtype, ip, ttl);
    return 0;
}

/**
 * 从缓存获取条目
 * @param cache 缓存管理器
 * @param domain 域名
 * @param qtype 查询类型
 * @return 缓存条目指针，未找到或过期返回NULL
 */
CacheEntry *cache_get(DNSCache *cache, const char *domain, uint16_t qtype) {
    if (!cache || !domain) {
        return NULL;
    }

    char key[270];
    cache_key_generate(key, domain, qtype);

    CacheEntry *entry;
    HASH_FIND_STR(cache->entries, key, entry);

    if (!entry) {
        cache->stats.misses++;
        return NULL;
    }

    // 检查是否过期
    uint32_t remaining = cache_get_remaining_ttl(entry);
    if (remaining <= 0) {
        print_debug_info("缓存过期：%s (%u)\n", domain, qtype);
        HASH_DEL(cache->entries, entry);
        free(entry);
        cache->stats.current_size--;
        cache->stats.expired++;
        cache->stats.misses++;
        return NULL;
    }

    // 先删除再插入，保持LRU顺序
    HASH_DEL(cache->entries, entry);
    HASH_ADD_STR(cache->entries, key, entry);

    cache->stats.hits++;

    print_debug_info("缓存命中：%s (%u) -> %s, 剩余TTL=%u秒\n", domain, qtype, entry->ip, remaining);

    return entry;
}

//清理过期的缓存条目
void cache_cleanup_expired(DNSCache *cache) {
    if (!cache) return;

    CacheEntry *entry, *tmp;
    uint32_t expired_count = 0;

    HASH_ITER(hh, cache->entries, entry, tmp) {
        if (cache_get_remaining_ttl(entry) <= 0) {
            HASH_DEL(cache->entries, entry);
            free(entry);
            cache->stats.current_size--;
            cache->stats.expired++;
            expired_count++;
        }
    }

    if (expired_count > 0) {
        print_debug_info("清理过期缓存：删除%u个条目\n", expired_count);
    }
}

//计算缓存命中率
double cache_hit_rate(const DNSCache *cache) {
    if (!cache) return 0.0;
    uint64_t total = cache->stats.hits + cache->stats.misses;
    if (total == 0) return 0.0;
    return (double)cache->stats.hits / (double)total;
}

//打印缓存统计信息
void cache_print_stats(const DNSCache *cache) {
    if (!cache) return;

    print_debug_info("=== DNS缓存统计 ===\n");
    print_debug_info("当前大小: %u/%u\n", cache->stats.current_size, cache->stats.max_size);
    print_debug_info("命中次数: %llu\n", cache->stats.hits);
    print_debug_info("未命中次数: %llu\n", cache->stats.misses);
    print_debug_info("命中率: %.2f%%\n", cache_hit_rate(cache) * 100.0);
    print_debug_info("过期条目: %llu\n", cache->stats.expired);
    print_debug_info("驱逐条目: %llu\n", cache->stats.evicted);
    print_debug_info("==================\n");
}