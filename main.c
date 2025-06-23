#include "table.h"
#include "protocol.h"
#include "main.h"


// 全局变量
static RelayEntry *relay_table = NULL;  // ID映射表
static uint16_t next_upstream_id = 1;   // 下一个可用的上游ID


// 上游DNS服务器配置
#define UPSTREAM_DNS_IP "10.3.9.5"
#define UPSTREAM_DNS_PORT 53

#define RELAY_TIMEOUT 5  // 超时时间（秒）
time_t last_cleanup = 0;

// ID映射表结构定义
typedef struct relay_entry {
    uint16_t upstream_id;           // 转发到上游的新ID
    uint16_t client_id;            // 客户端原始ID
    struct sockaddr_in client_addr; // 客户端地址
    time_t timestamp;              // 时间戳，用于超时处理
    UT_hash_handle hh;             // uthash处理句柄
} RelayEntry;

// 全局变量
static RelayEntry *relay_table = NULL;  // ID映射表
static uint16_t next_upstream_id = 1;   // 下一个可用的上游ID



// 调试信息输出函数声明
void print_debug_info(const char* format, ...);

// 生成新的上游ID
uint16_t generate_upstream_id() {
    uint16_t id = next_upstream_id++;
    if (next_upstream_id == 0) next_upstream_id = 1;  // 避免0
    return id;
}

// 清理超时的映射记录
void cleanup_expired_entries(time_t timeout) {
    RelayEntry *entry, *tmp;
    time_t now = time(NULL);
    
    HASH_ITER(hh, relay_table, entry, tmp) {
        if (now - entry->timestamp > timeout) {
            HASH_DEL(relay_table, entry);
            free(entry);
        }
    }
}


// DNS服务器主循环，负责接收、解析、应答DNS查询
int start_dns_server(DNSRecord* table) {
    SOCKET sock;
    SOCKET upstream_sock; 
    struct sockaddr_in server_addr;
    struct sockaddr_in upstream_addr;
    uint8_t recv_buffer[MAX_DNS_PACKET_SIZE]; // 接收缓冲区
    uint8_t send_buffer[MAX_DNS_PACKET_SIZE]; // 发送缓冲区
    char domain[MAX_DOMAIN_LENGTH];           // 解析出的域名
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        print_debug_info("WSAStartup失败\n");
        return -1;
    }
#endif


    // 创建本地DNS服务器socket
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == INVALID_SOCKET) {
        print_debug_info("创建本地套接字失败\n");
        return -1;
    }

    // 创建上游DNS服务器socket
    upstream_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (upstream_sock == INVALID_SOCKET) {
        print_debug_info("创建上游DNS套接字失败\n");
        closesocket(sock);
        return -1;
    }


    // 绑定本地地址和端口
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(DNS_PORT);
    if (bind(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        print_debug_info("绑定套接字失败，请确保以管理员权限运行\n");
        closesocket(sock);
        return -1;
    }

    // 设置上游DNS服务器地址
    memset(&upstream_addr, 0, sizeof(upstream_addr));
    upstream_addr.sin_family = AF_INET;
    upstream_addr.sin_port = htons(UPSTREAM_DNS_PORT);
    #ifdef _WIN32
        upstream_addr.sin_addr.s_addr = inet_addr(UPSTREAM_DNS_IP);
    #else
        inet_pton(AF_INET, UPSTREAM_DNS_IP, &upstream_addr.sin_addr);
    #endif


    print_debug_info("DNS服务器启动，监听端口 %d\n", DNS_PORT);

    
    fd_set readfds;
    int maxfd = (sock > upstream_sock ? sock : upstream_sock) + 1;

    // 主循环：不断接收和处理DNS查询
    while (1) {
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);
        FD_SET(upstream_sock, &readfds);

        // 每60秒清理一次超时记录
        cleanup_expired_entries(60);

        int ret = select(maxfd, &readfds, NULL, NULL, NULL);
        if (ret < 0) continue;

        // 处理客户端请求
        if (FD_ISSET(sock, &readfds)) {
            struct sockaddr_in client_addr;
            int client_addr_len = sizeof(client_addr);
            int recv_len = recvfrom(sock, (char*)recv_buffer, sizeof(recv_buffer), 0,
                                  (struct sockaddr*)&client_addr, &client_addr_len);

            if (recv_len < DNS_HEADER_SIZE) {
                continue;
            }

            DNSHeader* header = (DNSHeader*)recv_buffer;
            if (ntohs(header->qdcount) != 1) {
                continue;
            }

            int qname_len = parse_dns_name(recv_buffer, DNS_HEADER_SIZE, domain, sizeof(domain));
            if (qname_len < 0) {
                continue;
            }

            DNSQuestion* question = (DNSQuestion*)(recv_buffer + DNS_HEADER_SIZE + qname_len);
            uint16_t qtype = ntohs(question->qtype);
            uint16_t qclass = ntohs(question->qclass);

            if (qtype != DNS_TYPE_A || qclass != DNS_CLASS_IN) {
                print_debug_info("收到非A类型或非IN类查询: %s\n", domain);
                int send_len = build_dns_error_response(send_buffer, recv_buffer, 
                    qname_len + sizeof(DNSQuestion), DNS_RCODE_NOT_IMPLEMENTED);
                sendto(sock, (char*)send_buffer, send_len, 0,
                       (struct sockaddr*)&client_addr, sizeof(client_addr));
                continue;
            }

            // 在本地表中查找
            DNSRecord* record;
            HASH_FIND_STR(table, domain, record);

            if (record && strcmp(record->ip, "0.0.0.0") != 0) {
                // 本地有记录，直接返回
                print_debug_info("找到记录 %s -> %s\n", domain, record->ip);
                int send_len = build_dns_response(send_buffer, recv_buffer, 
                    qname_len + sizeof(DNSQuestion), record->ip);
                sendto(sock, (char*)send_buffer, send_len, 0,
                       (struct sockaddr*)&client_addr, sizeof(client_addr));
            } else if (record && strcmp(record->ip, "0.0.0.0") == 0) {
                // 域名被拦截
                print_debug_info("域名被拦截 %s\n", domain);
                int send_len = build_dns_error_response(send_buffer, recv_buffer,
                    qname_len + sizeof(DNSQuestion), DNS_RCODE_NAME_ERROR);
                sendto(sock, (char*)send_buffer, send_len, 0,
                       (struct sockaddr*)&client_addr, sizeof(client_addr));
            } else {
                // 本地没有记录，转发到上游DNS
                print_debug_info("转发查询到上游DNS: %s\n", domain);
                uint16_t upstream_id = generate_upstream_id();
                RelayEntry *entry = malloc(sizeof(RelayEntry));
                if (entry) {
                    entry->upstream_id = upstream_id;
                    entry->client_id = ntohs(header->id);
                    entry->client_addr = client_addr;
                    entry->timestamp = time(NULL);
                    HASH_ADD(hh, relay_table, upstream_id, sizeof(uint16_t), entry);

                    // 修改请求ID并转发
                    header->id = htons(upstream_id);
                    sendto(upstream_sock, (char*)recv_buffer, recv_len, 0,
                           (struct sockaddr*)&upstream_addr, sizeof(upstream_addr));
                }
            }
        }

        // 处理上游DNS响应
        if (FD_ISSET(upstream_sock, &readfds)) {
            struct sockaddr_in from_addr;
            socklen_t from_len = sizeof(from_addr);
            int len = recvfrom(upstream_sock, (char*)send_buffer, sizeof(send_buffer), 0,
                             (struct sockaddr*)&from_addr, &from_len);

            if (len >= DNS_HEADER_SIZE) {
                DNSHeader* header = (DNSHeader*)send_buffer;
                uint16_t upstream_id = ntohs(header->id);
                RelayEntry* entry = NULL;
                HASH_FIND(hh, relay_table, &upstream_id, sizeof(uint16_t), entry);

                if (entry) {
                    // 恢复原始ID并转发给客户端
                    header->id = htons(entry->client_id);
                    sendto(sock, (char*)send_buffer, len, 0,
                           (struct sockaddr*)&entry->client_addr, sizeof(entry->client_addr));
                    HASH_DEL(relay_table, entry);
                    free(entry);
                }
            }
        }

        time_t now = time(NULL);
        if (now - last_cleanup >= 1) { // 每1秒检查一次
            RelayEntry *entry, *tmp;
            HASH_ITER(hh, relay_table, entry, tmp) {
                if (now - entry->timestamp > RELAY_TIMEOUT) {
                    // 构造超时错误响应并发回客户端
                    uint8_t timeout_buffer[MAX_DNS_PACKET_SIZE] = {0};
                    int send_len = build_timeout_response(timeout_buffer, entry->client_id, 2); // 2=Server failure
                    sendto(sock, (char*)timeout_buffer, send_len, 0,
                        (struct sockaddr*)&entry->client_addr, sizeof(entry->client_addr));
                    // 删除并释放
                    HASH_DEL(relay_table, entry);
                    free(entry);
                }
            }
            last_cleanup = now;
        }
    }

    closesocket(sock);
    closesocket(upstream_sock);
    #ifdef _WIN32
        WSACleanup();
    #endif
    return 0;
}

// 程序入口，负责加载表、启动服务器、释放资源
int main(int argc, char* argv[]) {
    DNSRecord* table = NULL;
    const char* filename = "dnsrelay.txt";
    // 加载DNS表
    if (load_dns_table(filename, &table) < 0) {
        return 1;
    }
    // 启动DNS服务器
    start_dns_server(table);
    // 释放DNS表
    free_dns_table(table);
    return 0;
}
