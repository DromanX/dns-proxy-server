#ifndef CONFIG_H
#define CONFIG_H

#include <arpa/inet.h>

typedef struct {
    char upstream_dns_server_ip[INET_ADDRSTRLEN];   // IP-адрес вышестоящего DNS
    char **blacklist;                               // Чёрный список доменных имён 
    int blacklist_size;                             // Размер чёрного списка
    char blacklist_response_type[16];               // Тип ответа для доменов в чёрном списке
    char fixed_ip[INET_ADDRSTRLEN];                 // Предварительно настроеный IP-адрес для доменов чёрном списке
} DnsProxyConfig;

void readConfig(const char *filename, DnsProxyConfig *config);

#endif
