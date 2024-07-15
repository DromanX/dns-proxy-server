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

void createResponse(unsigned char *response, const unsigned char *query, const DnsProxyConfig *config, unsigned short length_query) {
    DNSHeader *header = (DNSHeader *)response;
    memcpy(response, query, length_query);

    header->flags = htons(0x8180);
    if (strcmp(config->blacklist_response_type, "NOT_FOUND") == 0) {
        response[3] |= 0x03;
    } else if (strcmp(config->blacklist_response_type, "REFUSED") == 0) {
        response[4] |= 0x05;
    } else if (strcmp(config->blacklist_response_type, "FIXED_IP") == 0) {
        response[7] = 1;

        int pos = DNS_HEADER_SIZE;
        while (response[pos] != 0) {
            pos++;
        }
        pos += 5; // Перемещение к секции Answer

        response[pos++] = 0xC0;
        response[pos++] = 0x0C;
        response[pos++] = 0;
        response[pos++] = 1;
        response[pos++] = 0;
        response[pos++] = 1;
        response[pos++] = 0;
        response[pos++] = 0;
        response[pos++] = 0;
        response[pos++] = 0x78; // TTL = 120sec
        response[pos++] = 0;
        response[pos++] = 4;

        if (strlen(config->fixed_ip) > 0) {
            inet_pton(AF_INET, config->fixed_ip, response + pos);
        } else {
            printf("Не установлен IP-адрес для FIXED_IP в файле конфигурации. Установлен адрес по-умолчанию 0.0.0.0\n");
            memset(response + pos, 0, 4);
        }
    }
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
            printf("Домен %s находится в чёрном списке: %s\n", domain, config->blacklist_response_type);
            unsigned char response[MAX_PACKET_DNS_SIZE];
            createResponse(response, packet, config, received);
            sendto(sockfd, response, sizeof(response), 0, (const struct sockaddr *)&client_addr, client_len);
        } else {
            sendto(sockfd, packet, received, 0, (const struct sockaddr *)&upstream_dns_addr, sizeof(upstream_dns_addr));

            int upstrean_response = recvfrom(sockfd, packet, sizeof(packet), 0, NULL, NULL);
            if (upstrean_response > 0) {
                sendto(sockfd, packet, upstrean_response, 0, (const struct sockaddr *)&client_addr, client_len);
            }
        }
    }
    close(sockfd);
}
