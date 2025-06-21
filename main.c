#include "table.h"
#include "protocol.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
#else
    #include <unistd.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #define SOCKET int
    #define INVALID_SOCKET -1
    #define closesocket close
#endif

// 调试信息输出函数声明
void print_debug_info(const char* format, ...);

// DNS服务器主循环，负责接收、解析、应答DNS查询
int start_dns_server(DNSRecord* table) {
    SOCKET sock;
    struct sockaddr_in server_addr;
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
    // 创建UDP套接字
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == INVALID_SOCKET) {
        print_debug_info("创建套接字失败\n");
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
    print_debug_info("DNS服务器启动，监听端口 %d\n", DNS_PORT);
    // 主循环：不断接收和处理DNS查询
    while (1) {
        struct sockaddr_in client_addr;
        int client_addr_len = sizeof(client_addr);
        int recv_len, send_len, qname_len;
        DNSHeader* header;
        DNSRecord* record;
        DNSQuestion* question;
        // 接收DNS查询包
        recv_len = recvfrom(sock, (char*)recv_buffer, sizeof(recv_buffer), 0,
                           (struct sockaddr*)&client_addr, &client_addr_len);
        if (recv_len < DNS_HEADER_SIZE) {
            continue; // 包太短，丢弃
        }
        header = (DNSHeader*)recv_buffer;

        if (ntohs(header->qdcount) != 1) {
            continue;
        }
        // 解析域名
        qname_len = parse_dns_name(recv_buffer, DNS_HEADER_SIZE, domain, sizeof(domain));
        if (qname_len < 0) {
            continue;
        }
        // 用结构体操作问题区
        question = (DNSQuestion*)(recv_buffer + DNS_HEADER_SIZE + qname_len);
        uint16_t qtype = ntohs(question->qtype);
        uint16_t qclass = ntohs(question->qclass);
        // 只处理A类型（IPv4）和IN类
        if (qtype != DNS_TYPE_A || qclass != DNS_CLASS_IN) {
            print_debug_info("收到非A类型或非IN类查询: %s, type=%u, class=%u\n", domain, qtype, qclass);
            send_len = build_dns_error_response(send_buffer, recv_buffer, qname_len + sizeof(DNSQuestion), DNS_RCODE_NOT_IMPLEMENTED);
            sendto(sock, (char*)send_buffer, send_len, 0,
                   (struct sockaddr*)&client_addr, sizeof(client_addr));
            continue;
        }
        print_debug_info("收到A类型查询: %s\n", domain);
        // 查找域名对应的IP
        HASH_FIND_STR(table, domain, record);
        if (record && strcmp(record->ip, "0.0.0.0") != 0) {
            print_debug_info("找到记录 %s -> %s\n", domain, record->ip);
            if(strcmp(record->ip, "0.0.0.0") != 0) {
                send_len = build_dns_response(send_buffer, recv_buffer, qname_len + sizeof(DNSQuestion), record->ip);
            } else{
                send_len = build_dns_error_response(send_buffer, recv_buffer, qname_len + sizeof(DNSQuestion), DNS_RCODE_NAME_ERROR);
            }
        } else {
            print_debug_info("未找到记录 %s\n", domain);
            send_len = build_dns_error_response(send_buffer, recv_buffer, qname_len + sizeof(DNSQuestion), DNS_RCODE_NAME_ERROR);
        }
        sendto(sock, (char*)send_buffer, send_len, 0,
               (struct sockaddr*)&client_addr, sizeof(client_addr));
    }
    closesocket(sock);
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
