#ifndef MAIN_H
#define MAIN_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "uthash.h"
#include <time.h>

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


// 上游DNS服务器配置
#define UPSTREAM_DNS_IP "10.3.9.5"
#define UPSTREAM_DNS_PORT 53
#define RELAY_TIMEOUT 1  // 超时时间（秒）

// ID映射表结构定义
typedef struct relay_entry {
    uint16_t upstream_id;           // 转发到上游的新ID
    uint16_t client_id;            // 客户端原始ID
    struct sockaddr_in client_addr; // 客户端地址
    struct timeval timestamp;              // 时间戳，用于超时处理
    UT_hash_handle hh;             // uthash处理句柄
} RelayEntry;

#endif // MAIN_H