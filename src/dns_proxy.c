#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../include/dns_proxy.h"
#include "../include/error_handler.h"

#define DNS_PORT 5454
#define DNS_DEFAULT_PORT 53
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
    memcpy(response, query, length_query);

    // FLAGS
    response[2] = 0x81;
    response[3] = 0x80;

    // Проверка типа ошибки заданной в конфигурации для доменов в чёрном списке и последующая модификация DNS-ответа
    if (strcmp(config->blacklist_response_type, "NOT_FOUND") == 0) {
        response[3] |= 0x03; // RCODE = NXDOMAIN
    } else if (strcmp(config->blacklist_response_type, "REFUSED") == 0) {
        response[4] |= 0x05; // RCODE = REFUSED
    } else if (strcmp(config->blacklist_response_type, "FIXED_IP") == 0) {
        response[7] = 1;

        int pos = DNS_HEADER_SIZE; // Текущая позиция байта в DNS-ответе

        while (response[pos] != 0) {
            pos++;
        }
        pos += 5; // Перемещение к секции Answer

        // NAME
        response[pos++] = 0xC0;
        response[pos++] = 0x0C;
        // TYPE = A
        response[pos++] = 0;
        response[pos++] = 1;
        // CLASS = IN
        response[pos++] = 0;
        response[pos++] = 1;
        // TTL = 120 sec
        response[pos++] = 0;
        response[pos++] = 0;
        response[pos++] = 0;
        response[pos++] = 0x78;
        // RDLENGTH = 4
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

volatile sig_atomic_t running = 1;

void signalHandler(int signum) {
    (void)signum;
    running = 0;
}

void runServer(const DnsProxyConfig *config) {

    // Установка обработки сигналов для завершения работы
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);

    // Сокет сервера для связи с клиентом
    int sockfd = Socket(AF_INET, SOCK_DGRAM, 0);

    // Сокет сервера для связи с вышестоящим DNS-сервером и установка для него неблокирующего режима
    int upstream_sockfd = Socket(AF_INET, SOCK_DGRAM, 0);
    int flags = fcntl(upstream_sockfd, F_GETFL, 0);
    fcntl(upstream_sockfd, F_SETFL, flags | O_NONBLOCK);

    // Структуры для представления адреса и порта сокетов сервера, клиента и вышестоящего DNS-сервера
    struct sockaddr_in server_addr = { 0 }, client_addr = { 0 }, upstream_dns_addr = { 0 };

    // Настройка адреса для сокета сервера
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(DNS_PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;
    socklen_t server_len = sizeof(server_addr);
    // Привязка сокета сервера к адресу
    Bind(sockfd, (const struct sockaddr *)&server_addr, server_len);

    // Настройка адреса для сокета вышестоящего DNS-сервера
    upstream_dns_addr.sin_family = AF_INET;
    upstream_dns_addr.sin_port = htons(DNS_DEFAULT_PORT);
    Inet_pton(AF_INET, config->upstream_dns_server_ip, &upstream_dns_addr.sin_addr);

    if (running)
        printf("DNS-прокси-сервер запущен...\n");
    
    while (running) {
        // Массив двух структур для мониторинга сокетов
        struct pollfd fds[2];

        // Client
        fds[0].fd = sockfd;
        fds[0].events = POLLIN;
        // Upstream DNS
        fds[1].fd = upstream_sockfd;
        fds[1].events = POLLIN;

        // Ожидание события на одном из сокетов
        int ret = Poll(fds, 2, -1);
        if (ret > 0) {
            if (fds[0].revents & POLLIN) {
                fds[0].revents = 0;

                unsigned char packet[MAX_PACKET_DNS_SIZE];
                socklen_t client_len = sizeof(client_addr);

                ssize_t received = Recvfrom(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&client_addr, &client_len);
                if (received < 0)
                    continue;

                char domain[256];
                extractDomain(packet, domain);
                printf("Получен запрос для домена: %s\n", domain);

                if (isDomainBlacklisted(domain, config)) {
                    printf("Домен %s находится в чёрном списке: %s\n", domain, config->blacklist_response_type);
                    unsigned char response[MAX_PACKET_DNS_SIZE];
                    createResponse(response, packet, config, received);
                    Sendto(sockfd, response, sizeof(response), 0, (const struct sockaddr *)&client_addr, client_len);
                } else {
                    Sendto(upstream_sockfd, packet, received, 0, (const struct sockaddr *)&upstream_dns_addr, sizeof(upstream_dns_addr));

                    // Ожидание ответа от вышестоящего сервера с таймаутом в 5 секунд
                    ret = Poll(&fds[1], 1, 5000);
                    if (ret > 0) {
                        if (fds[1].revents & POLLIN) {
                            int upstream_response = Recvfrom(upstream_sockfd, packet, sizeof(packet), 0, NULL, NULL);
                            if (upstream_response > 0) {
                                Sendto(sockfd, packet, upstream_response, 0, (const struct sockaddr *)&client_addr, client_len);
                            }
                        }
                    } else {
                        printf("Таймаут ожидания ответа от вышестоящего DNS-сервера\n");
                    }
                }
            }
        }
    }
    printf("Завершение работы DNS-proxy-сервера...\n");
    close(upstream_sockfd);
    close(sockfd);
}