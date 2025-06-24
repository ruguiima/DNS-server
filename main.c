#include "protocol.h"
#include "util.h"
#include "table.h"
#include "server.h"
#include "cache.h"
#include <signal.h>

#define MY_PORT 53
#define UPSTREAM_DNS_IP "10.3.9.5"

// 缓存配置常量
#define CACHE_MAX_ENTRIES 1000 // 最大缓存条目数
#define CACHE_DEFAULT_TTL 300  // 默认TTL 5分钟
#define CACHE_MIN_TTL 60       // 最小TTL 1分钟
#define CACHE_MAX_TTL 86400    // 最大TTL 24小时

// 增加全局退出标志
static volatile sig_atomic_t g_exit_flag = 0;

// 资源释放函数
void free_dns_context(DNSContext *ctx)
{
    if (!ctx)
        return;
    closesocket(ctx->sock);
    closesocket(ctx->upstream_sock);
#ifdef _WIN32
    WSACleanup();
#endif
    free_relay_table(ctx->relay_table);
    free_dns_table(ctx->dns_table);
    if (ctx->cache)
    {
        cache_destroy(ctx->cache);
    }
}

// SIGINT信号处理函数
void handle_sigint(int sig)
{
    print_debug_info("收到SIGINT，准备退出...\n");
    g_exit_flag = 1;
}

// 负责启动DNS查询
int start_dns_server(DNSContext *context)
{
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        print_debug_info("WSAStartup失败\n");
        return -1;
    }
#endif

    struct sockaddr_in server_addr;

    // 创建本地监听UDP套接字
    context->sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (context->sock == INVALID_SOCKET)
    {
        print_debug_info("创建本地套接字失败\n");
        return -1;
    }

    // 创建上游DNS通信UDP套接字
    context->upstream_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (context->upstream_sock == INVALID_SOCKET)
    {
        print_debug_info("创建上游DNS套接字失败\n");
        closesocket(context->sock);
        return -1;
    }

    // 配置本地监听地址
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(MY_PORT);
    if (bind(context->sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        print_debug_info("绑定套接字失败，请确保以管理员权限运行\n");
        closesocket(context->sock);
        closesocket(context->upstream_sock);
        return -1;
    }

    // 配置上游DNS服务器地址
    memset(&context->upstream_addr, 0, sizeof(context->upstream_addr));
    context->upstream_addr.sin_family = AF_INET;
    context->upstream_addr.sin_port = htons(DNS_PORT);
#ifdef _WIN32
    context->upstream_addr.sin_addr.s_addr = inet_addr(UPSTREAM_DNS_IP);
#else
    inet_pton(AF_INET, UPSTREAM_DNS_IP, &context->upstream_addr.sin_addr);
#endif

    print_debug_info("DNS服务器启动，监听端口 %d\n", MY_PORT);
    return 0;
}

// ======================= 程序入口 =======================
// 负责加载表、启动服务器、释放资源
int main(int argc, char *argv[])
{
    DNSContext context = {0}; // 初始化上下文
    context.dns_table = NULL;
    context.relay_table = NULL;
    context.upstream_id_counter = 0;
    context.cache = NULL;

    signal(SIGINT, handle_sigint);

    // 初始化缓存
    context.cache = cache_create(CACHE_MAX_ENTRIES, CACHE_DEFAULT_TTL,
                                 CACHE_MIN_TTL, CACHE_MAX_TTL);
    if (!context.cache)
    {
        print_debug_info("缓存初始化失败\n");
        return 1;
    }

    // 初始化缓存清理时间
    get_now(&context.last_cache_cleanup);

    const char *filename = "dnsrelay.txt";
    // 加载本地DNS表
    if (load_dns_table(filename, &context.dns_table) < 0)
    {
        return 1;
    }

    if (start_dns_server(&context) < 0)
    {
        free_dns_context(&context);
        return 1;
    }

    uint8_t recv_buffer[MAX_DNS_PACKET_SIZE];
    uint8_t upstream_recv_buffer[MAX_DNS_PACKET_SIZE];

    fd_set readfds;
    int maxfd = (context.sock > context.upstream_sock ? context.sock : context.upstream_sock) + 1;

    // ======================= 主循环 =======================
    while (!g_exit_flag)
    {
        FD_ZERO(&readfds);
        FD_SET(context.sock, &readfds);
        FD_SET(context.upstream_sock, &readfds);

        // 设置select超时时间，定期处理转发表超时
        struct timeval tv = {0, 100000};
        int ret = select(maxfd, &readfds, NULL, NULL, &tv);

        if (ret < 0)
        {
            // select出错，打印错误信息
            perror("select error");
            continue;
        }
        if (ret == 0)
        {
            // 超时，无事件发生，检查并处理转发表超时请求
            handle_timed_out_requests(&context);

            // 定期清理过期缓存
            struct timeval now;
            get_now(&now);
            if (now.tv_sec - context.last_cache_cleanup.tv_sec >= CACHE_CLEANUP_INTERVAL)
            {
                cache_cleanup_expired(context.cache);
                context.last_cache_cleanup = now;
            }
        }

        // 检查本地监听套接字是否有数据（来自客户端的查询）
        if (FD_ISSET(context.sock, &readfds))
        {
            struct sockaddr_in client_addr;
            socklen_t client_addr_len = sizeof(client_addr);
            int recv_len = recvfrom(context.sock, (char *)recv_buffer, sizeof(recv_buffer), 0,
                                    (struct sockaddr *)&client_addr, &client_addr_len);
            if (recv_len > 0)
            {
                // 收到客户端查询，进行处理
                handle_client_query(&context, client_addr, recv_buffer, recv_len);
            }
        }

        // 检查上游DNS套接字是否有数据（来自上游的响应）
        if (FD_ISSET(context.upstream_sock, &readfds))
        {
            struct sockaddr_in from_addr;
            socklen_t from_len = sizeof(from_addr);
            int len = recvfrom(context.upstream_sock, (char *)upstream_recv_buffer, sizeof(upstream_recv_buffer), 0,
                               (struct sockaddr *)&from_addr, &from_len);
            if (len > 0)
            {
                // 收到上游响应，进行处理
                handle_upstream_response(&context, upstream_recv_buffer, len);
            }
        }
    }
    print_debug_info("退出主循环，释放所有资源...\n");
    // 关闭套接字，清理资源
    free_dns_context(&context);
    return 0;
}
