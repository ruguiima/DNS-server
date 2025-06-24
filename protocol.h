#ifndef DNS_PROTOCOL_H
#define DNS_PROTOCOL_H

#include <string.h>
#include <stdint.h>
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


// DNS报文固定头部长度为12字节
#define DNS_HEADER_SIZE 12
// 标准DNS端口
#define DNS_PORT 53
// 最大域名长度
#define MAX_DOMAIN_LENGTH 256
// 最大UDP报文长度
#define MAX_DNS_PACKET_SIZE 512

// DNS报文头部结构
#pragma pack(push, 1)  // 按1字节对齐
typedef struct dns_header {
    uint16_t id;       // 会话标识
    uint16_t flags;    // 各种标志位
    uint16_t qdcount;  // 问题数
    uint16_t ancount;  // 回答数
    uint16_t nscount;  // 授权记录数
    uint16_t arcount;  // 附加记录数
} DNSHeader;

// DNS问题区结构体
typedef struct dns_question {
    // 域名部分需单独处理
    uint16_t qtype;    // 查询类型
    uint16_t qclass;   // 查询类
} DNSQuestion;

// DNS资源记录结构体
typedef struct dns_rr {
    uint16_t name;    // 资源记录名称（通常是域名，使用压缩指针）
    uint16_t type;     // 记录类型
    uint16_t class;    // 记录类
    uint32_t ttl;      // 生存时间
    uint16_t rdlength; // 资源数据长度
} DNS_RR;

#pragma pack(pop)

// DNS响应码
#define DNS_RCODE_NO_ERROR 0
#define DNS_RCODE_SERVER_FAILURE 2
#define DNS_RCODE_NAME_ERROR 3
#define DNS_RCODE_NOT_IMPLEMENTED 4

// DNS记录类型
#define DNS_TYPE_A 1             // IPv4地址记录
#define DNS_TYPE_AAAA 28         // IPv6地址记录
#define DNS_CLASS_IN 1           // Internet类

int parse_dns_name(const uint8_t* data, int offset, char* domain, int maxlen);
int build_standard_dns_response(uint8_t* response, const uint8_t* request, 
                       int question_len, const char* ip);
int build_ipv6_dns_response(uint8_t* response, const uint8_t* request, 
                             int question_len, const char* ip);
// 构造DNS查询失败响应包（如Name Error等）
int build_dns_error_response(uint8_t* response, const uint8_t* request,
                             int question_len, uint16_t rcode);

#endif /* DNS_PROTOCOL_H */
