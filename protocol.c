#include "protocol.h"
#include <string.h>
#include <stdint.h>
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
#else
    #include <arpa/inet.h>
#endif

// 解析DNS查询包中的域名
int parse_dns_name(const uint8_t* data, int offset, char* domain, int maxlen) {
    int i = 0, j = 0;
    uint8_t len;
    while ((len = data[offset + i]) != 0) {
        if (i > 0) {
            domain[j++] = '.';
        }
        i++;
        memcpy(domain + j, data + offset + i, len);
        i += len;
        j += len;
        if (j >= maxlen - 1) {
            return -1;
        }
    }
    domain[j] = '\0';
    return i + 1; // 返回处理的字节数
}

// 构造DNS响应包
int build_dns_response(uint8_t* response, const uint8_t* request, 
                       int question_len, const char* ip) {
    DNSHeader* header;
    uint8_t* ptr;
    uint32_t ip_addr;
    // 1. 复制请求包头
    memcpy(response, request, sizeof(DNSHeader));
    // 2. 复制原始问题区
    memcpy(response + sizeof(DNSHeader), request + sizeof(DNSHeader), question_len);
    ptr = response + sizeof(DNSHeader) + question_len;
    // 3. 设置flags
    header = (DNSHeader*)response;
    header->flags &= htons(~(DNS_FLAG_QR | DNS_FLAG_AA | DNS_FLAG_RA | DNS_FLAG_RCODE));
    header->flags |= htons(DNS_FLAG_QR | DNS_FLAG_AA | DNS_FLAG_RA);

    header->flags |= htons(DNS_RCODE_NO_ERROR);
    header->ancount = htons(1);
    // 5. 构造资源记录（A记录）
    // 回答区域名（压缩指针）
    *ptr++ = 0xC0; *ptr++ = 0x0C;
    DNSResourceRecord* rr = (DNSResourceRecord*)ptr;
    rr->type = htons(DNS_TYPE_A);
    rr->class = htons(DNS_CLASS_IN);
    rr->ttl = htonl(300);
    rr->rdlength = htons(4);
    inet_pton(AF_INET, ip, rr->rdata);
    ptr += sizeof(DNSResourceRecord);
    return ptr - response;
}

// 构造DNS错误响应包，rcode为响应码
int build_dns_error_response(uint8_t* response, const uint8_t* request, int question_len, uint16_t rcode) {
    DNSHeader* header = (DNSHeader*)response;
    // 1. 复制请求包头
    memcpy(response, request, sizeof(DNSHeader));
    // 2. 复制原始问题区
    memcpy(response + sizeof(DNSHeader), request + sizeof(DNSHeader), question_len);
    // 3. 设置flags
    header->flags &= htons(~(DNS_FLAG_QR | DNS_FLAG_AA | DNS_FLAG_RA | DNS_FLAG_RCODE));
    header->flags |= htons(DNS_FLAG_QR | DNS_FLAG_AA | DNS_FLAG_RA);
    header->flags |= htons(rcode);
    header->ancount = 0;
    // 4. 返回包长度（无应答区）
    return sizeof(DNSHeader) + question_len;
}
