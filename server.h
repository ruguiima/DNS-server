#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "uthash.h"

#define RELAY_TIMEOUT 1  // 超时时间（秒）

// 封装了服务器运行所需的所有状态
typedef struct {
    int sock;                       // 本地监听套接字
    int upstream_sock;              // 上游通信套接字
    struct sockaddr_in upstream_addr; // 上游服务器地址
    DNSRecord *dns_table;               // 本地DNS记录表
    RelayEntry *relay_table;        // 转发请求记录表
    uint16_t upstream_id_counter;   // 用于生成唯一上游请求ID的计数器
} DNSContext;

void handle_timed_out_requests(DNSContext *ctx);
void forward_query_to_upstream(DNSContext *ctx, const uint8_t* query_buffer, int query_len, 
                               int question_section_len, struct sockaddr_in client_addr);

void handle_upstream_response(DNSContext *ctx, uint8_t *response_buffer, int response_len);
void handle_client_query(DNSContext *ctx, struct sockaddr_in client_addr, 
                         uint8_t *query_buffer, int query_len);