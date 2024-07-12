#ifndef DNS_PROXY_H
#define DNS_PROXY_H

#include "config.h"

typedef struct {
    unsigned short id;
    unsigned short flags;
    unsigned short qdcount;
    unsigned short ancount;
    unsigned short nscount;
    unsigned short arcount;
} DNSHeader;

void runServer(const DnsProxyConfig *config);

#endif