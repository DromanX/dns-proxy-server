#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../include/dns_proxy.h"

#define DNS_PORT 5454
#define MAX_PACKET_DNS_SIZE 512
#define DNS_HEADER_SIZE 12

int isDomainBlacklisted(const char *domain, const DnsProxyConfig *config) {
    for (int i = 0; i < config->blacklist_size; i++) {
        if (strcmp(domain, config->blacklist[i]) == 0)
            return 1;
    }
    return 0;
}

void extractDomain(const unsigned char *packet, char *domain) {
    const unsigned char *pos = packet + DNS_HEADER_SIZE;
    int length_domain = 0;
    int j = 0;
    while (*pos != 0) {
        length_domain = *pos;
        for (int i = 0; i < length_domain; i++) {
            domain[j++] = *++pos;
        }
        domain[j++] = '.';
        ++pos;
    }
    domain[--j] = '\0';
}

void createResponse(unsigned char *response, const unsigned char *query, const DnsProxyConfig *config) {
    DNSHeader *header = (DNSHeader *)response;
    memcpy(response, query, 12);
}

void runServer(const DnsProxyConfig *config) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Не удалось создать сокет");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in server_addr = { 0 }, client_addr = { 0 }, upstream_dns_addr = { 0 };

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(DNS_PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;
    socklen_t server_len = sizeof(server_addr);

    if (bind(sockfd, (const struct sockaddr *)&server_addr, server_len) < 0) {
        perror("Не удалось привязать сокет");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    upstream_dns_addr.sin_family = AF_INET;
    upstream_dns_addr.sin_port = htons(53);
    int res = inet_pton(AF_INET, config->upstream_dns_server_ip, &upstream_dns_addr.sin_addr);

    if (res == 0) {
        perror("Отсутствует адрес вышестоящего DNS-сервера");
        exit(EXIT_FAILURE);
    } else if (res < 0) {
        perror("Неверный формат ip-адреса вышестоящего DNS-сервера");
        exit(EXIT_FAILURE);
    }

    printf("DNS-прокси-сервер запущен...\n");

    while (1) {
        unsigned char packet[MAX_PACKET_DNS_SIZE];
        socklen_t client_len = sizeof(client_addr);
        ssize_t received = recvfrom(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&client_addr, &client_len);

        if (received < 0) {
            perror("Ошибка при получении данных от клиента");
            continue;
        }

        char domain[256];
        extractDomain(packet, domain);
        printf("Получен запрос для домена: %s\n", domain);

        if (isDomainBlacklisted(domain, config)) {
            printf("Домен %s в чёрном списке", domain);
            unsigned char response[MAX_PACKET_DNS_SIZE];
            createResponse(response, packet, config);

        } else {
        }
    }
}