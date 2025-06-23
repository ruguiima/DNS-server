#ifndef DNS_PROTOCOL_H
#define DNS_PROTOCOL_H

#include <string.h>
#include <stdint.h>
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
#else
    #include <arpa/inet.h>
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
    // 域名部分需单独处理
    uint16_t type;     // 记录类型
    uint16_t class;    // 记录类
    uint32_t ttl;      // 生存时间
    uint16_t rdlength; // 资源数据长度
    uint8_t  rdata[4]; // 资源数据（这里只考虑A记录，IPv4地址4字节）
} DNSResourceRecord;

#pragma pack(pop)

// DNS响应码
#define DNS_RCODE_NO_ERROR 0      // 没有错误
#define DNS_RCODE_NAME_ERROR 3    // 域名不存在
#define DNS_RCODE_NOT_IMPLEMENTED 4 // 未实现的查询类型

// DNS标志位
#define DNS_FLAG_QR 0x8000        // 查询/响应标志，1为响应
#define DNS_FLAG_AA 0x0400        // 授权回答
#define DNS_FLAG_TC 0x0200        // 可截断的
#define DNS_FLAG_RD 0x0100        // 期望递归
#define DNS_FLAG_RA 0x0080        // 可用递归
#define DNS_FLAG_RCODE 0x000F     // 响应码掩码

// DNS记录类型
#define DNS_TYPE_A 1             // IPv4地址记录
#define DNS_CLASS_IN 1           // Internet类

int parse_dns_name(const uint8_t* data, int offset, char* domain, int maxlen);
int build_dns_response(uint8_t* response, const uint8_t* request, 
                       int question_len, const char* ip);
// 构造DNS查询失败响应包（如Name Error等）
int build_dns_error_response(uint8_t* response, const uint8_t* request,
                             int question_len, uint16_t rcode);


//构造超时响应报文
int build_timeout_response(uint8_t* response, uint16_t id, uint16_t rcode);
#endif /* DNS_PROTOCOL_H */
