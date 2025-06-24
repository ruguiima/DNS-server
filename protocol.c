#include "protocol.h"

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

// 构造ipv4 DNS响应包
int build_standard_dns_response(uint8_t* response, const uint8_t* request, 
                       int question_len, const char* ip) {
    DNSHeader* header;
    uint32_t ip_addr;
    // 1. 复制请求包头
    memcpy(response, request, sizeof(DNSHeader));
    // 2. 复制原始问题区
    memcpy(response + sizeof(DNSHeader), request + sizeof(DNSHeader), question_len);
    // 3. 设置flags
    header = (DNSHeader*)response;
    header->flags = htons(0x8180);
    header->ancount = htons(1);
    // 5. 构造资源记录（A记录）
    DNS_RR* rr = (DNS_RR*)(response + sizeof(DNSHeader) + question_len);
    // 回答区域名（压缩指针）
    rr->name = htons(0xC00C);
    rr->type = htons(DNS_TYPE_A);
    rr->class = htons(DNS_CLASS_IN);
    rr->ttl = htonl(300);
    rr->rdlength = htons(4);
    inet_pton(AF_INET, ip, (uint8_t*)rr + sizeof(DNS_RR));
    return sizeof(DNSHeader) + question_len + sizeof(DNS_RR) + 4; // 返回包长度
}

// 构造IPv6 DNS响应包
int build_ipv6_dns_response(uint8_t* response, const uint8_t* request, 
                             int question_len, const char* ip) {
    DNSHeader* header;
    // 1. 复制请求包头
    memcpy(response, request, sizeof(DNSHeader));
    // 2. 复制原始问题区
    memcpy(response + sizeof(DNSHeader), request + sizeof(DNSHeader), question_len);
    // 3. 设置flags
    header = (DNSHeader*)response;
    header->flags = htons(0x8180);
    header->ancount = htons(1);
    // 5. 构造资源记录（AAAA记录）
    DNS_RR* rr = (DNS_RR*)(response + sizeof(DNSHeader) + question_len);
    // 回答区域名（压缩指针）
    rr->name = htons(0xC00C);
    rr->type = htons(DNS_TYPE_AAAA);
    rr->class = htons(DNS_CLASS_IN);
    rr->ttl = htonl(300);
    rr->rdlength = htons(16);
    inet_pton(AF_INET6, ip, (uint8_t*)rr + sizeof(DNS_RR));
    return sizeof(DNSHeader) + question_len + sizeof(DNS_RR) + 16; // 返回包长度
}

// 构造DNS错误响应包，rcode为响应码
int build_dns_error_response(uint8_t* response, const uint8_t* request, 
                             int question_len, uint16_t rcode) {
    DNSHeader* header = (DNSHeader*)response;
    memcpy(response, request, sizeof(DNSHeader));
    memcpy(response + sizeof(DNSHeader), request + sizeof(DNSHeader), question_len);
    header->flags = htons(0x8180 | rcode);
    header->ancount = 0;
    return sizeof(DNSHeader) + question_len;
}

