#ifndef MAIN_H
#define MAIN_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "uthash.h"
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

#endif // MAIN_H