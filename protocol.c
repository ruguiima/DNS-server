#include "protocol.h"

// 解析DNS查询包中的域名
int parse_dns_name(const uint8_t* data, int offset, char* domain, int maxlen) {
    int i = offset, j = 0;
    uint8_t len;
    int jumped = 0;         // 标记是否遇到压缩指针
    int i_origin;    // 保存主路径偏移

    while ((len = data[i]) != 0) {
        // 检查是否是压缩指针（最高两位为11）
        if ((len & 0xC0) == 0xC0) {
            if (!jumped) {
                i_origin = i;  // 记录此时的i
                jumped = 1;
            }
            // 提取压缩指针偏移量（两个字节）
            i = ((len & 0x3F) << 8) | data[i + 1];
        } else {
        i++;  // 跳过长度字节
        // 每个 label 前加 '.'（除了第一个）
        if (j > 0) domain[j++] = '.';
        if (j + len >= maxlen - 1) return -1;
        memcpy(domain + j, data + i, len);
        i += len;  j += len;
        }
    }
    domain[j] = '\0';
    return jumped ? i_origin + 2 - offset : i + 1 - offset;
}


// 构造DNS响应包
int build_standard_dns_response(uint8_t* response, const uint8_t* request, int question_len, const char* ip) {
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
    return sizeof(DNSHeader) + question_len + 2 + sizeof(DNS_RR) + 4;  // 返回包长度
}

// 构造IPv6 DNS响应包
int build_ipv6_dns_response(uint8_t* response, const uint8_t* request, int question_len, const char* ip) {
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
    return sizeof(DNSHeader) + question_len + 2 + sizeof(DNS_RR) + 16;  // 返回包长度
}

// 构造DNS错误响应包，rcode为响应码
int build_dns_error_response(uint8_t* response, const uint8_t* request, int question_len, uint16_t rcode) {
    DNSHeader* header = (DNSHeader*)response;
    memcpy(response, request, sizeof(DNSHeader));
    memcpy(response + sizeof(DNSHeader), request + sizeof(DNSHeader), question_len);
    header->flags = htons(0x8180 | rcode);
    header->ancount = 0;
    return sizeof(DNSHeader) + question_len;
}
