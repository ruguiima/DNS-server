#include "protocol.h"

int parse_dns_name(const uint8_t* data, int offset, char* domain, int maxlen) {
    int i = 0, j = 0;
    uint8_t len;

    while ((len = data[offset + i]) != 0) {
        // 检查是否是压缩指针（最高两位为11）
        if ((len & 0xC0) == 0xC0) {
            // 遇到压缩指针，返回2字节长度，置domain为空串
            domain[0] = '\0';
            return i + 2;
        }
        // 每个 label 前加 '.'（除了第一个）
        if (i > 0) {
            if (j >= maxlen - 1) return -1;
            domain[j++] = '.';
        }
        i++;  // 跳过长度字节
        if (j + len >= maxlen - 1) return -1;
        memcpy(domain + j, data + offset + i, len);
        j += len;
        i += len;
    }

    domain[j] = '\0';
    return i + 1; // 返回消耗的字节数（包括结尾0）
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
    // 4. 回答区域名（压缩指针）
    uint16_t* name = (uint16_t*)(response + sizeof(DNSHeader) + question_len);
    *name = htons(0xC00C);
    // 5. 构造资源记录（A记录）
    DNS_RR* rr = (DNS_RR*)(name + 1);
    rr->type = htons(DNS_TYPE_A);
    rr->class = htons(DNS_CLASS_IN);
    rr->ttl = htonl(300);
    rr->rdlength = htons(4);
    inet_pton(AF_INET, ip, (uint8_t*)rr + sizeof(DNS_RR));
    return sizeof(DNSHeader) + question_len + 2 + sizeof(DNS_RR) + 4; // 返回包长度
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
    // 4. 回答区域名（压缩指针）
    uint16_t* name = (uint16_t*)(response + sizeof(DNSHeader) + question_len);
    *name = htons(0xC00C);
    // 5. 构造资源记录（A记录）
    DNS_RR* rr = (DNS_RR*)(name + 1);
    rr->type = htons(DNS_TYPE_AAAA);
    rr->class = htons(DNS_CLASS_IN);
    rr->ttl = htonl(300);
    rr->rdlength = htons(16);
    inet_pton(AF_INET6, ip, (uint8_t*)rr + sizeof(DNS_RR));
    return sizeof(DNSHeader) + question_len + 2 + sizeof(DNS_RR) + 16; // 返回包长度
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

