#include "cache.h"
#include "protocol.h"
#include "table.h"
#include "util.h"
#include "server.h"



/**
 * @brief 处理超时的转发请求。
 * @param ctx 指向DNS服务器上下文的指针。
 */
void handle_timed_out_requests(DNSContext *ctx) {
    struct timeval now;
    get_now(&now);

    RelayEntry *entry, *tmp;
    HASH_ITER(hh, ctx->relay_table, entry, tmp) {
        long sec_diff = now.tv_sec - entry->timestamp.tv_sec;
        long usec_diff = now.tv_usec - entry->timestamp.tv_usec;

        if (sec_diff > RELAY_TIMEOUT || (sec_diff == RELAY_TIMEOUT && usec_diff > 0)) {
            print_debug_info("RelayEntry超时: upstream_id=%u, client_id=%u, 域名请求超时未响应，发送Server failure\n",
                             entry->upstream_id, entry->client_id);

            uint8_t timeout_buffer[MAX_DNS_PACKET_SIZE] = {0};
            int send_len =
                build_dns_error_response(timeout_buffer, entry->query, entry->question_len, DNS_RCODE_SERVER_FAILURE);
            sendto(ctx->sock, (char *)timeout_buffer, send_len, 0, (struct sockaddr *)&entry->client_addr,
                   sizeof(entry->client_addr));

            HASH_DEL(ctx->relay_table, entry);
            free(entry);
        }
    }
}

/**
 * @brief 将查询转发到上游DNS服务器。
 * @param ctx 指向DNS服务器上下文的指针。
 * @param query_buffer 包含原始客户端查询的缓冲区。
 * @param query_len 查询的长度。
 * @param client_addr 原始客户端的地址信息。
 */
void forward_query_to_upstream(DNSContext *ctx, const uint8_t *query_buffer, int query_len, int question_section_len,
                               struct sockaddr_in client_addr) {
    RelayEntry *entry = malloc(sizeof(RelayEntry));
    if (!entry) {
        print_debug_info("分配RelayEntry失败，无法转发查询\n");
        return;
    }

    DNSHeader *header = (DNSHeader *)query_buffer;

    entry->upstream_id = ++(ctx->upstream_id_counter);
    entry->client_id = ntohs(header->id);
    entry->client_addr = client_addr;
    memcpy(entry->query, query_buffer, query_len);
    entry->question_len = question_section_len;
    get_now(&entry->timestamp);
    HASH_ADD(hh, ctx->relay_table, upstream_id, sizeof(uint16_t), entry);

    // 创建一个副本进行修改，避免污染原始的接收缓冲区
    uint8_t forward_buffer[MAX_DNS_PACKET_SIZE];
    memcpy(forward_buffer, query_buffer, query_len);
    DNSHeader *forward_header = (DNSHeader *)forward_buffer;
    forward_header->id = htons(entry->upstream_id);

    sendto(ctx->upstream_sock, (char *)forward_buffer, query_len, 0, (struct sockaddr *)&ctx->upstream_addr,
           sizeof(ctx->upstream_addr));
}

/**
 * @brief 处理来自客户端的DNS查询。
 * @param ctx 指向DNS服务器上下文的指针。
 * @param client_addr 发起查询的客户端地址。
 * @param query_buffer 包含查询数据的缓冲区。
 * @param query_len 查询数据的长度。
 */
void handle_client_query(DNSContext *ctx, struct sockaddr_in client_addr, uint8_t *query_buffer, int query_len) {
    char domain[256];                              // 将domain作为局部变量
    uint8_t response_buffer[MAX_DNS_PACKET_SIZE];  // 用于发送响应的独立缓冲区

    // ----------- 基本校验 -----------
    // 检查数据包长度是否合法
    if (query_len < DNS_HEADER_SIZE) {
        print_debug_info("收到的数据包长度过小: %d 字节\n", query_len);
        return;
    }
    DNSHeader *header = (DNSHeader *)query_buffer;
    // 检查问题数是否为1
    if (ntohs(header->qdcount) != 1) {
        print_debug_info("收到的查询问题数不是1: %d\n", ntohs(header->qdcount));
        return;
    }

    // ----------- 解析域名 -----------
    // 从DNS报文中解析出域名
    int qname_len = parse_dns_name(query_buffer, DNS_HEADER_SIZE, domain, sizeof(domain));
    if (qname_len < 0) {
        print_debug_info("解析域名失败\n");
        return;
    }
    // 获取查询类型和类
    DNSQuestion *question = (DNSQuestion *)(query_buffer + DNS_HEADER_SIZE + qname_len);
    uint16_t qtype = ntohs(question->qtype);
    uint16_t qclass = ntohs(question->qclass);
    int question_section_len = qname_len + sizeof(DNSQuestion);

    // ----------- 类型判断 -----------
    // 只处理A和AAAA类型的IN类查询，其他类型直接返回未实现
    int is_a = (qtype == DNS_TYPE_A && qclass == DNS_CLASS_IN);
    int is_aaaa = (qtype == DNS_TYPE_AAAA && qclass == DNS_CLASS_IN);
    if (!is_a && !is_aaaa) {
        print_debug_info("收到非A/AAAA类型或非IN类查询: %s\n", domain);
        int send_len =
            build_dns_error_response(response_buffer, query_buffer, question_section_len, DNS_RCODE_NOT_IMPLEMENTED);
        sendto(ctx->sock, (char *)response_buffer, send_len, 0, (struct sockaddr *)&client_addr, sizeof(client_addr));
        return;
    }
    // ----------- 查询本地表 -----------
    // 在本地DNS表中查找域名
    DNSRecord *record;
    HASH_FIND_STR(ctx->dns_table, domain, record);
    if (record) {
        // 命中本地表，判断是否为拦截（0.0.0.0）
        if (strcmp(record->ip, "0.0.0.0") == 0) {
            print_debug_info("域名被拦截 %s\n", domain);
            int send_len =
                build_dns_error_response(response_buffer, query_buffer, question_section_len, DNS_RCODE_NAME_ERROR);
            sendto(ctx->sock, (char *)response_buffer, send_len, 0, (struct sockaddr *)&client_addr,
                   sizeof(client_addr));
            return;
        }

        // 命中A记录，直接返回本地IP
        if (is_a) {
            print_debug_info("找到记录 %s -> %s\n", domain, record->ip);
            int send_len = build_standard_dns_response(response_buffer, query_buffer, question_section_len, record->ip);
            sendto(ctx->sock, (char *)response_buffer, send_len, 0, (struct sockaddr *)&client_addr,
                   sizeof(client_addr));
            return;
        } else {
            // 有A记录但收到AAAA查询，返回空应答
            print_debug_info("本地表有A记录，对AAAA查询返回空应答: %s\n", domain);
            int send_len =
                build_dns_error_response(response_buffer, query_buffer, question_section_len, DNS_RCODE_NO_ERROR);
            sendto(ctx->sock, (char *)response_buffer, send_len, 0, (struct sockaddr *)&client_addr,
                   sizeof(client_addr));
            return;
        }
    }
    // ----------- 查询缓存 -----------
    CacheEntry *cache_entry = cache_get(ctx->cache, domain, qtype);
    if (cache_entry) {
        // 命中缓存，直接返回缓存的IP
        if (is_a && cache_entry->qtype == DNS_TYPE_A) {
            int send_len = build_standard_dns_response(response_buffer, query_buffer, question_section_len, cache_entry->ip);
            sendto(ctx->sock, (char *)response_buffer, send_len, 0, (struct sockaddr *)&client_addr,
                   sizeof(client_addr));
            return;
        } else if (is_aaaa && cache_entry->qtype == DNS_TYPE_AAAA) {
            int send_len = build_ipv6_dns_response(response_buffer, query_buffer, question_section_len, cache_entry->ip);
            sendto(ctx->sock, (char *)response_buffer, send_len, 0, (struct sockaddr *)&client_addr,
                   sizeof(client_addr));
            return;
        }
    }
    // 未命中，转发到上游DNS服务器
    print_debug_info("转发%s查询到上游DNS: %s\n", is_a ? "A" : "AAAA", domain);
    forward_query_to_upstream(ctx, query_buffer, query_len, question_section_len, client_addr);
}

// ----------- 更新缓存 -----------
void update_cache(DNSContext *ctx, uint8_t *response_buffer) {
    int ancount = ntohs(((DNSHeader *)response_buffer)->ancount);
    if (ancount <= 0) return;

    // 先解析问题区，得到qname_len，跳过问题区
    char q_domain[256] = "";
    int qname_len = parse_dns_name(response_buffer, DNS_HEADER_SIZE, q_domain, sizeof(q_domain));
    if (qname_len < 0) {
        print_debug_info("update_cache: 问题区域名解析失败\n");
        return;
    }
    int offset = DNS_HEADER_SIZE + qname_len + sizeof(DNSQuestion);
    for (int i = 0; i < ancount; i++) {
        char rr_domain[256] = "";
        int rr_name_len = parse_dns_name(response_buffer, offset, rr_domain, sizeof(rr_domain));
        if (rr_name_len < 0) {
            print_debug_info("update_cache: 回答区域名解析失败\n");
            return;
        }
        DNS_RR *rr = (DNS_RR *)(response_buffer + offset + rr_name_len);

        uint16_t type = ntohs(rr->type);
        uint16_t rdlength = ntohs(rr->rdlength);
        const uint8_t *rdata = response_buffer + offset + rr_name_len + sizeof(DNS_RR);

        if (type == DNS_TYPE_A && rdlength == 4) {
            char ip[16];
            inet_ntop(AF_INET, rdata, ip, sizeof(ip));
            cache_put(ctx->cache, q_domain, DNS_TYPE_A, ip, rr->ttl);
            return;
        } else if (type == DNS_TYPE_AAAA && rdlength == 16) {
            char ip[46];
            inet_ntop(AF_INET6, rdata, ip, sizeof(ip));
            cache_put(ctx->cache, q_domain, DNS_TYPE_AAAA, ip, rr->ttl);
            return;
        }
        print_debug_info("update_cache: 不支持的记录类型或长度不匹配，type=%u, rdlength=%u\n", type, rdlength);
        offset += rr_name_len + sizeof(DNS_RR) + rdlength;  // 移动到下一个记录
    }
}

/**
 * @brief 处理来自上游DNS服务器的响应。
 * @param ctx 指向DNS服务器上下文的指针。
 * @param response_buffer 包含上游响应的缓冲区。
 * @param response_len 响应的长度。
 */
void handle_upstream_response(DNSContext *ctx, uint8_t *response_buffer, int response_len) {
    // 检查上游响应长度是否合法，防止无效包
    if (response_len < DNS_HEADER_SIZE) {
        print_debug_info("收到的上游响应长度过小: %d 字节\n", response_len);
        return;
    }

    // 解析上游响应的ID，用于在转发表中查找对应的请求
    DNSHeader *header = (DNSHeader *)response_buffer;
    uint16_t resp_upstream_id = ntohs(header->id);
    RelayEntry *entry = NULL;
    HASH_FIND(hh, ctx->relay_table, &resp_upstream_id, sizeof(uint16_t), entry);

    if (entry) {
        update_cache(ctx, response_buffer);  // 更新缓存
        // 找到对应的转发请求，恢复原始客户端ID并转发响应
        print_debug_info("收到上游响应，转发给客户端，upstream_id=%u, client_id=%u\n", resp_upstream_id,
                         entry->client_id);
        header->id = htons(entry->client_id);
        sendto(ctx->sock, (char *)response_buffer, response_len, 0, (struct sockaddr *)&entry->client_addr,
               sizeof(entry->client_addr));

        // 转发完成后移除转发表项，释放内存
        HASH_DEL(ctx->relay_table, entry);
        free(entry);
    } else {
        // 未找到对应请求，说明已超时或非法响应，直接丢弃
        print_debug_info("未找到对应的RelayEntry, upstream_id=%u，丢弃响应\n", resp_upstream_id);
    }
}
