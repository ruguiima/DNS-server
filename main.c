#include "protocol.h"
#include "util.h"
#include "table.h"
#include "server.h"

#define UPSTREAM_DNS_PORT 53
#define UPSTREAM_DNS_IP "10.3.9.5"

// 负责接收、解析、应答DNS查询
int start_dns_server(DNSRecord* initial_table) {
    DNSContext context = {0}; // 初始化上下文
    context.table = initial_table;
    context.relay_table = NULL;
    context.upstream_id_counter = 0;

    struct sockaddr_in server_addr;
    uint8_t recv_buffer[MAX_DNS_PACKET_SIZE];
    uint8_t upstream_recv_buffer[MAX_DNS_PACKET_SIZE];

#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        print_debug_info("WSAStartup失败\n");
        return -1;
    }
#endif

    // 创建本地监听UDP套接字
    context.sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (context.sock == INVALID_SOCKET) {
        print_debug_info("创建本地套接字失败\n");
        return -1;
    }

    // 创建上游DNS通信UDP套接字
    context.upstream_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (context.upstream_sock == INVALID_SOCKET) {
        print_debug_info("创建上游DNS套接字失败\n");
        closesocket(context.sock);
        return -1;
    }

    // 配置本地监听地址
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(DNS_PORT);
    if (bind(context.sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        print_debug_info("绑定套接字失败，请确保以管理员权限运行\n");
        closesocket(context.sock);
        closesocket(context.upstream_sock);
        return -1;
    }

    // 配置上游DNS服务器地址
    memset(&context.upstream_addr, 0, sizeof(context.upstream_addr));
    context.upstream_addr.sin_family = AF_INET;
    context.upstream_addr.sin_port = htons(UPSTREAM_DNS_PORT);
#ifdef _WIN32
    context.upstream_addr.sin_addr.s_addr = inet_addr(UPSTREAM_DNS_IP);
#else
    inet_pton(AF_INET, UPSTREAM_DNS_IP, &context.upstream_addr.sin_addr);
#endif

    print_debug_info("DNS服务器启动，监听端口 %d\n", DNS_PORT);

    fd_set readfds;
    int maxfd = (context.sock > context.upstream_sock ? context.sock : context.upstream_sock) + 1;

    // ======================= 主循环 =======================
    while (1) {
        FD_ZERO(&readfds);
        FD_SET(context.sock, &readfds);
        FD_SET(context.upstream_sock, &readfds);

        // 设置select超时时间，定期处理转发表超时
        struct timeval tv = {0, 100000};
        int ret = select(maxfd, &readfds, NULL, NULL, &tv);

        if (ret < 0) {
            // select出错，打印错误信息
            perror("select error");
            continue;
        }

        if (ret == 0) {
            // 超时，无事件发生，检查并处理转发表超时请求
            handle_timed_out_requests(&context);
        }
        
        // 检查本地监听套接字是否有数据（来自客户端的查询）
        if (FD_ISSET(context.sock, &readfds)) {
            struct sockaddr_in client_addr;
            socklen_t client_addr_len = sizeof(client_addr);
            int recv_len = recvfrom(context.sock, (char*)recv_buffer, sizeof(recv_buffer), 0,
                                    (struct sockaddr*)&client_addr, &client_addr_len);
            if (recv_len > 0) {
                // 收到客户端查询，进行处理
                handle_client_query(&context, client_addr, recv_buffer, recv_len);
            }
        }

        // 检查上游DNS套接字是否有数据（来自上游的响应）
        if (FD_ISSET(context.upstream_sock, &readfds)) {
            struct sockaddr_in from_addr;
            socklen_t from_len = sizeof(from_addr);
            int len = recvfrom(context.upstream_sock, (char*)upstream_recv_buffer, sizeof(upstream_recv_buffer), 0,
                               (struct sockaddr*)&from_addr, &from_len);
            if (len > 0) {
                // 收到上游响应，进行处理
                handle_upstream_response(&context, upstream_recv_buffer, len);
            }
        }
    }

    // 关闭套接字，清理资源
    closesocket(context.sock);
    closesocket(context.upstream_sock);
#ifdef _WIN32
    WSACleanup();
#endif
    free_relay_table(context.relay_table);
    return 0;
}

// ======================= 程序入口 =======================
// 负责加载表、启动服务器、释放资源
int main(int argc, char* argv[]) {
    DNSRecord* table = NULL;
    const char* filename = "dnsrelay.txt";
    
    // 加载本地DNS表
    if (load_dns_table(filename, &table) < 0) {
        return 1;
    }
    
    // 启动DNS服务器主循环
    start_dns_server(table);
    
    // 程序退出前释放本地DNS表内存
    free_dns_table(table);
    return 0;
}

