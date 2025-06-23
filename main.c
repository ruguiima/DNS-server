#include "table.h"
#include "protocol.h"
#include "util.h"
#include "main.h"

// DNS服务器主循环，负责接收、解析、应答DNS查询
int start_dns_server(DNSRecord* table) {
    SOCKET sock;
    SOCKET upstream_sock; 
    struct sockaddr_in server_addr;
    struct sockaddr_in upstream_addr;
    uint8_t recv_buffer[MAX_DNS_PACKET_SIZE]; // 接收缓冲区
    uint8_t send_buffer[MAX_DNS_PACKET_SIZE]; // 发送缓冲区
    char domain[MAX_DOMAIN_LENGTH];           // 解析出的域名
    RelayEntry *relay_table = NULL;  // ID映射表

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
    int upstream_id = 0; // 上游ID从1开始

    // 主循环：不断接收和处理DNS查询
    while (1) {
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);
        FD_SET(upstream_sock, &readfds);

        struct timeval tv = {0, 100000}; // 100毫秒超时
        int ret = select(maxfd, &readfds, NULL, NULL, &tv);
        if (ret < 0) continue;
        // 超时处理：检查relay_table中的条目是否超时
        if (ret == 0) {

            struct timeval now;
            get_now(&now);
            RelayEntry *entry, *tmp;
            HASH_ITER(hh, relay_table, entry, tmp) {
                long sec_diff = now.tv_sec - entry->timestamp.tv_sec;
                long usec_diff = now.tv_usec - entry->timestamp.tv_usec;
                if (sec_diff > RELAY_TIMEOUT || (sec_diff == RELAY_TIMEOUT && usec_diff > 0)) {
                    // 添加超时处理debug日志
                    print_debug_info("RelayEntry超时: upstream_id=%u, client_id=%u, 域名请求超时未响应，发送Server failure\n", 
                        entry->upstream_id, entry->client_id);
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
        } 
        // 处理客户端请求
        if (FD_ISSET(sock, &readfds)) {
            struct sockaddr_in client_addr;
            int client_addr_len = sizeof(client_addr);
            int recv_len = recvfrom(sock, (char*)recv_buffer, sizeof(recv_buffer), 0,
                                (struct sockaddr*)&client_addr, &client_addr_len);

            if (recv_len < DNS_HEADER_SIZE) {
                print_debug_info("收到的数据包长度过小: %d 字节\n", recv_len);
                continue;
            }

            DNSHeader* header = (DNSHeader*)recv_buffer;
            if (ntohs(header->qdcount) != 1) {
                print_debug_info("收到的查询问题数不是1: %d\n", ntohs(header->qdcount));
                continue;
            }

            int qname_len = parse_dns_name(recv_buffer, DNS_HEADER_SIZE, domain, sizeof(domain));
            if (qname_len < 0) {
                print_debug_info("解析域名失败\n");
                continue;
            }

            DNSQuestion* question = (DNSQuestion*)(recv_buffer + DNS_HEADER_SIZE + qname_len);
            uint16_t qtype = ntohs(question->qtype);
            uint16_t qclass = ntohs(question->qclass);

            // 合并A和AAAA类型的处理逻辑
            int is_a = (qtype == DNS_TYPE_A && qclass == DNS_CLASS_IN);
            int is_aaaa = (qtype == DNS_TYPE_AAAA && qclass == DNS_CLASS_IN);
            if (is_a || is_aaaa) {
                DNSRecord* record;
                HASH_FIND_STR(table, domain, record);
                if (record && strcmp(record->ip, "0.0.0.0") != 0) {
                    // 有记录且不是拦截，根据类型分别处理
                    if (is_a) {
                        print_debug_info("找到记录 %s -> %s\n", domain, record->ip);
                        int send_len = build_dns_response(send_buffer, recv_buffer, 
                            qname_len + sizeof(DNSQuestion), record->ip);
                        sendto(sock, (char*)send_buffer, send_len, 0,
                            (struct sockaddr*)&client_addr, sizeof(client_addr));
                    } else if (is_aaaa) {
                        print_debug_info("本地表有A记录，返回空应答: %s\n", domain);
                        int send_len = build_dns_empty_response(send_buffer, recv_buffer, qname_len + sizeof(DNSQuestion));
                        sendto(sock, (char*)send_buffer, send_len, 0,
                            (struct sockaddr*)&client_addr, sizeof(client_addr));
                    }
                } else if (record && strcmp(record->ip, "0.0.0.0") == 0) {
                    // 有记录且被拦截，A和AAAA都拦截
                    print_debug_info("域名被拦截 %s\n", domain);
                    int send_len = build_dns_error_response(send_buffer, recv_buffer,
                        qname_len + sizeof(DNSQuestion), DNS_RCODE_NAME_ERROR);
                    sendto(sock, (char*)send_buffer, send_len, 0,
                        (struct sockaddr*)&client_addr, sizeof(client_addr));
                } else {
                    // 无记录，A和AAAA都转发
                    print_debug_info("转发%s查询到上游DNS: %s\n", is_a ? "A" : "AAAA", domain);
                    RelayEntry *entry = malloc(sizeof(RelayEntry));
                    if (entry) {
                        entry->upstream_id = ++upstream_id;
                        entry->client_id = ntohs(header->id);
                        entry->client_addr = client_addr;
                        get_now(&entry->timestamp);
                        HASH_ADD(hh, relay_table, upstream_id, sizeof(uint16_t), entry);
                        header->id = htons(upstream_id);
                        sendto(upstream_sock, (char*)recv_buffer, recv_len, 0,
                            (struct sockaddr*)&upstream_addr, sizeof(upstream_addr));
                    } else {
                        print_debug_info("分配RelayEntry失败，无法转发%s查询: %s\n", is_a ? "A" : "AAAA", domain);
                    }
                }
                
            } else{
                // 其它类型直接返回未实现
                print_debug_info("收到非A/AAAA类型或非IN类查询: %s\n", domain);
                int send_len = build_dns_error_response(send_buffer, recv_buffer, 
                    qname_len + sizeof(DNSQuestion), DNS_RCODE_NOT_IMPLEMENTED);
                sendto(sock, (char*)send_buffer, send_len, 0,
                    (struct sockaddr*)&client_addr, sizeof(client_addr));
            }                
        }

        // 处理上游DNS响应
        else if (FD_ISSET(upstream_sock, &readfds)) {
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
                    print_debug_info("收到上游响应，转发给客户端，upstream_id=%u, client_id=%u\n", upstream_id, entry->client_id);
                    header->id = htons(entry->client_id);
                    sendto(sock, (char*)send_buffer, len, 0,
                        (struct sockaddr*)&entry->client_addr, sizeof(entry->client_addr));
                    HASH_DEL(relay_table, entry);
                    free(entry);
                } else {
                    print_debug_info("未找到对应的RelayEntry, upstream_id=%u，丢弃响应\n", upstream_id);
                }
            } else {
                print_debug_info("收到的上游响应长度过小: %d 字节\n", len);
            }
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
