#include <stdio.h> // Структура FILE
#include <stdlib.h> // Функция realloc()
// #include <string.h> // Функция strtok()
#include <sys/socket.h> // Функция socket()
#include <sys/types.h> //
#include <unistd.h> // Функция close()

#include "../include/config.h"
#include "../include/dns_proxy.h"

#define CONFIG_FILE "../config/dns_proxy.conf"
#define MAX_PACKET_SIZE 512
#define SA struct sockaddr
// #define PORT_DNS 5353

/*  Проверка доменного имени в чёрном списке  */
int isBlacklisted(const char *domain, DnsProxyConfig *config) {
    for (int i = 0; i < config->blacklist_size; i++) {
        if (strcmp(domain, config->blacklist[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

/*  Извлечение доменного имени из DNS-запроса  */
void extractDomainName(const unsigned char *buffer, char *domain) {
    const unsigned char *ptr = buffer + 12;
    char *pos = domain;
    while (*ptr != 0) {
        int len = *ptr++;
        for (int i = 0; i < len; i++) {
            *pos++ = *ptr++;
        }
        *pos++ = '.';
    }
    *--pos = '\0';
}

/*  Обработка входящего DNS-запроса  */
void handleRequest(int sockfd, struct sockaddr_in *client_addr, socklen_t client_len, DnsProxyConfig *config) {
    char response[MAX_PACKET_SIZE];
    ssize_t received = recvfrom(sockfd, response, sizeof(response), 0, (SA *)client_addr, &client_len);

    if (received < 0) {
        perror("Не удалось получить данные");
        return;
    }

    char domain[256];
    extractDomainName((const unsigned char *)response, domain);

    if (isBlacklisted((const char *)domain, config)) {
        printf("Домен заблокирован: %s\n", domain);

        if (strcmp(config->blacklist_response_type, "NOT_FOUND") == 0) {
            response[3] |= 0x03;
        } else if (strcmp(config->blacklist_response_type, "DENIED") == 0) {
            response[3] |= 0x05;
        } else if (strcmp(config->blacklist_response_type, "FIXED_IP") == 0) {
            struct in_addr addr;
            int res = inet_pton(AF_INET, config->fixed_ip, &addr);
            if (res == 0) {
                printf("src не содержит строку символов, представляющую действительный сетевой адрес в указанном семействе адресов.\n");
                exit(EXIT_FAILURE);
            }
            if (res == -1) {
                perror("inet_pton failed");
                exit(EXIT_FAILURE);
            }

            memset(&response[received - 4], 0, 4); // RDATA = 00 00 00 00
            memcpy(&response[received - 4], &addr, sizeof(addr)); // RDATA = FIXED_IP
            response[3] |= 0xF0;
        }
        sendto(sockfd, response, received, 0, (const SA *)client_addr, client_len);
    } else {
        // Перенаправляем запрос на вышестоящий DNS-сервер и получаем ответ
        struct sockaddr_in dns_server_addr = { 0 };
        dns_server_addr.sin_family = AF_INET;
        dns_server_addr.sin_port = htons(53);
        inet_pton(AF_INET, config->upstream_dns_server_ip, &dns_server_addr.sin_addr);

        sendto(sockfd, response, received, 0, (const SA *)&dns_server_addr, sizeof(dns_server_addr));

        ssize_t dns_response_size = recvfrom(sockfd, response, sizeof(response), 0, NULL, NULL);

        if (dns_response_size < 0) {
            perror("Ошибка получения данных от вышестоящего DNS-сервера");
            return;
        }

        sendto(sockfd, response, dns_response_size, 0, (const SA *)client_addr, client_len);
    }
}

int main() {
    DnsProxyConfig config = { 0 };
    readConfig(CONFIG_FILE, &config);

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Не удалось создать сокет");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in server_addr = { 0 };
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(5454);

    if (bind(sockfd, (SA *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Ошибка привязки");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in client_addr = { 0 };
    socklen_t client_len = sizeof(client_addr);
    while (1) {
        handleRequest(sockfd, &client_addr, client_len, &config);
    }

    close(sockfd);

    for (int i = 0; i < config.blacklist_size; i++) {
        free(config.blacklist[i]);
    }
    free(config.blacklist);

    return 0;
}