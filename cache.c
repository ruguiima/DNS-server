#include "cache.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * 创建DNS缓存管理器
 * @param max_entries 最大缓存条目数
 * @param default_ttl 默认TTL（秒）
 * @param min_ttl 最小TTL（秒）
 * @param max_ttl 最大TTL（秒）
 * @return 缓存管理器指针，失败返回NULL
 */
DNSCache *cache_create(uint32_t max_entries, uint32_t default_ttl,
                       uint32_t min_ttl, uint32_t max_ttl)
{
    DNSCache *cache = malloc(sizeof(DNSCache));
    if (!cache)
    {
        print_debug_info("缓存创建失败：内存分配错误\n");
        return NULL;
    }

    memset(cache, 0, sizeof(DNSCache));
    cache->entries = NULL;
    cache->max_entries = max_entries;
    cache->default_ttl = default_ttl;
    cache->min_ttl = min_ttl;
    cache->max_ttl = max_ttl;

    print_debug_info("DNS缓存已创建：最大条目=%u, 默认TTL=%u秒\n",
                     max_entries, default_ttl);
    return cache;
}

/**
 * 销毁DNS缓存管理器
 * @param cache 缓存管理器指针
 */
void cache_destroy(DNSCache *cache)
{
    if (!cache)
        return;

    CacheEntry *entry, *tmp;
    HASH_ITER(hh, cache->entries, entry, tmp)
    {
        HASH_DEL(cache->entries, entry);
        free(entry);
    }

    print_debug_info("DNS缓存已销毁：命中率=%.2f%%, 总命中=%llu, 总未命中=%llu\n",
                     cache_hit_rate(cache), cache->stats.hits, cache->stats.misses);
    free(cache);
}

/**
 * 生成缓存键（域名+查询类型）
 * @param key 输出键字符串
 * @param domain 域名
 * @param qtype 查询类型
 */
void cache_key_generate(char *key, const char *domain, uint16_t qtype)
{
    snprintf(key, 270, "%s#%u", domain, qtype);
}

/**
 * 给时间值添加秒数
 * @param tv 时间值指针
 * @param seconds 要添加的秒数
 */
void timeval_add_seconds(struct timeval *tv, uint32_t seconds)
{
    tv->tv_sec += seconds;
}

/**
 * 检查缓存条目是否过期
 * @param entry 缓存条目
 * @return 1表示过期，0表示未过期
 */
int cache_is_expired(const CacheEntry *entry)
{
    struct timeval now;
    get_now(&now);

    return (now.tv_sec > entry->expire_time.tv_sec ||
            (now.tv_sec == entry->expire_time.tv_sec &&
             now.tv_usec > entry->expire_time.tv_usec));
}

/**
 * 获取缓存条目剩余TTL
 * @param entry 缓存条目
 * @return 剩余TTL秒数，已过期返回0
 */
uint32_t cache_get_remaining_ttl(const CacheEntry *entry)
{
    if (cache_is_expired(entry))
    {
        return 0;
    }

    struct timeval now;
    get_now(&now);

    long remaining = entry->expire_time.tv_sec - now.tv_sec;
    return (uint32_t)(remaining > 0 ? remaining : 0);
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
int cache_put(DNSCache *cache, const char *domain, uint16_t qtype,
              const char *ip, uint32_t ttl)
{
    if (!cache || !domain || !ip)
    {
        return -1;
    }

    // 调整TTL到合理范围
    if (ttl < cache->min_ttl)
        ttl = cache->min_ttl;
    if (ttl > cache->max_ttl)
        ttl = cache->max_ttl;

    char key[270];
    cache_key_generate(key, domain, qtype);

    // 检查是否已存在，如果存在则更新
    CacheEntry *existing;
    HASH_FIND_STR(cache->entries, key, existing);

    if (existing)
    {
        // 更新现有条目
        strncpy(existing->ip, ip, sizeof(existing->ip) - 1);
        existing->ip[sizeof(existing->ip) - 1] = '\0';
        existing->ttl = ttl;
        get_now(&existing->created_time);
        existing->expire_time = existing->created_time;
        timeval_add_seconds(&existing->expire_time, ttl);

        print_debug_info("缓存更新：%s (%u) -> %s, TTL=%u秒\n",
                         domain, qtype, ip, ttl);
        return 0;
    }

    // 检查缓存大小限制
    if (cache->stats.current_size >= cache->max_entries)
    {
        cache_evict_lru(cache);
    }

    // 创建新条目
    CacheEntry *entry = malloc(sizeof(CacheEntry));
    if (!entry)
    {
        print_debug_info("缓存添加失败：内存分配错误\n");
        return -1;
    }

    strncpy(entry->domain, key, sizeof(entry->domain) - 1);
    entry->domain[sizeof(entry->domain) - 1] = '\0';
    strncpy(entry->ip, ip, sizeof(entry->ip) - 1);
    entry->ip[sizeof(entry->ip) - 1] = '\0';
    entry->qtype = qtype;
    entry->ttl = ttl;

    get_now(&entry->created_time);
    entry->expire_time = entry->created_time;
    timeval_add_seconds(&entry->expire_time, ttl);

    HASH_ADD_STR(cache->entries, domain, entry);
    cache->stats.current_size++;

    print_debug_info("缓存添加：%s (%u) -> %s, TTL=%u秒\n",
                     domain, qtype, ip, ttl);
    return 0;
}

/**
 * 从缓存获取条目
 * @param cache 缓存管理器
 * @param domain 域名
 * @param qtype 查询类型
 * @return 缓存条目指针，未找到或过期返回NULL
 */
CacheEntry *cache_get(DNSCache *cache, const char *domain, uint16_t qtype)
{
    if (!cache || !domain)
    {
        return NULL;
    }

    char key[270];
    cache_key_generate(key, domain, qtype);

    CacheEntry *entry;
    HASH_FIND_STR(cache->entries, key, entry);

    if (!entry)
    {
        cache->stats.misses++;
        return NULL;
    }

    // 检查是否过期
    if (cache_is_expired(entry))
    {
        print_debug_info("缓存过期：%s (%u)\n", domain, qtype);
        HASH_DEL(cache->entries, entry);
        free(entry);
        cache->stats.current_size--;
        cache->stats.expired++;
        cache->stats.misses++;
        return NULL;
    }

    cache->stats.hits++;
    uint32_t remaining = cache_get_remaining_ttl(entry);
    print_debug_info("缓存命中：%s (%u) -> %s, 剩余TTL=%u秒\n",
                     domain, qtype, entry->ip, remaining);

    return entry;
}

/**
 * 从缓存删除条目
 * @param cache 缓存管理器
 * @param domain 域名
 * @param qtype 查询类型
 * @return 0成功，-1失败
 */
int cache_remove(DNSCache *cache, const char *domain, uint16_t qtype)
{
    if (!cache || !domain)
    {
        return -1;
    }

    char key[270];
    cache_key_generate(key, domain, qtype);

    CacheEntry *entry;
    HASH_FIND_STR(cache->entries, key, entry);

    if (entry)
    {
        HASH_DEL(cache->entries, entry);
        free(entry);
        cache->stats.current_size--;
        print_debug_info("缓存删除：%s (%u)\n", domain, qtype);
        return 0;
    }

    return -1;
}

/**
 * 清理过期的缓存条目
 * @param cache 缓存管理器
 */
void cache_cleanup_expired(DNSCache *cache)
{
    if (!cache)
        return;

    CacheEntry *entry, *tmp;
    uint32_t expired_count = 0;

    HASH_ITER(hh, cache->entries, entry, tmp)
    {
        if (cache_is_expired(entry))
        {
            HASH_DEL(cache->entries, entry);
            free(entry);
            cache->stats.current_size--;
            cache->stats.expired++;
            expired_count++;
        }
    }

    if (expired_count > 0)
    {
        print_debug_info("清理过期缓存：删除%u个条目\n", expired_count);
    }
}

/**
 * 驱逐最老的缓存条目（简单LRU）
 * @param cache 缓存管理器
 */
void cache_evict_lru(DNSCache *cache)
{
    if (!cache || !cache->entries)
        return;

    CacheEntry *oldest = NULL;
    CacheEntry *entry, *tmp;

    // 查找最老的条目（创建时间最早）
    HASH_ITER(hh, cache->entries, entry, tmp)
    {
        if (!oldest ||
            entry->created_time.tv_sec < oldest->created_time.tv_sec ||
            (entry->created_time.tv_sec == oldest->created_time.tv_sec &&
             entry->created_time.tv_usec < oldest->created_time.tv_usec))
        {
            oldest = entry;
        }
    }

    if (oldest)
    {
        print_debug_info("LRU驱逐：%s\n", oldest->domain);
        HASH_DEL(cache->entries, oldest);
        free(oldest);
        cache->stats.current_size--;
        cache->stats.evicted++;
    }
}

/**
 * 计算缓存命中率
 * @param cache 缓存管理器
 * @return 命中率（0.0-1.0）
 */
double cache_hit_rate(const DNSCache *cache)
{
    if (!cache)
        return 0.0;

    uint64_t total = cache->stats.hits + cache->stats.misses;
    if (total == 0)
        return 0.0;

    return (double)cache->stats.hits / (double)total;
}

/**
 * 打印缓存统计信息
 * @param cache 缓存管理器
 */
void cache_print_stats(const DNSCache *cache)
{
    if (!cache)
        return;

    print_debug_info("=== DNS缓存统计 ===\n");
    print_debug_info("当前大小: %u/%u\n", cache->stats.current_size, cache->max_entries);
    print_debug_info("命中次数: %llu\n", cache->stats.hits);
    print_debug_info("未命中次数: %llu\n", cache->stats.misses);
    print_debug_info("命中率: %.2f%%\n", cache_hit_rate(cache) * 100.0);
    print_debug_info("过期条目: %llu\n", cache->stats.expired);
    print_debug_info("驱逐条目: %llu\n", cache->stats.evicted);
    print_debug_info("==================\n");
}
