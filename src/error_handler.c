#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>

#include "../include/error_handler.h"

int Socket(int domain, int type, int protocol) {
    int res = socket(domain, type, protocol);
    if (res == -1) {
        perror("Не удалось создать сокет");
        exit(EXIT_FAILURE);
    }
    return res;
}

void Bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    int res = bind(sockfd, addr, addrlen);
    if (res == -1) {
        perror("Не удалось привязать IP-адрес к сокету");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
}

void Inet_pton(int af, const char *src, void *dst) {
    int res = inet_pton(af, src, dst);
    if (res == 0) {
        perror("Отсутствует адрес вышестоящего DNS-сервера");
        exit(EXIT_FAILURE);
    } else if (res < 0) {
        perror("Неверный формат ip-адреса вышестоящего DNS-сервера");
        exit(EXIT_FAILURE);
    }
}

int Recvfrom(int sockfd, void *data, size_t datalen, int flags, struct sockaddr *addr, socklen_t *addrlen) {
    int res = recvfrom(sockfd, data, datalen, flags, addr, addrlen);
    if (res == -1) {
        perror("Ошибка при получении данных");
    }
    return res;
}

void Sendto(int sockfd, const void *data, size_t datalen, int flags, const struct sockaddr *addr, socklen_t addrlen) {
    int res = sendto(sockfd, data, datalen, flags, addr, addrlen);
    if (res == -1) {
        perror("Ошибка при отправке данных");
    }
}

int Poll(struct pollfd *fds, nfds_t nfds, int timeout) {
    int res = poll(fds, nfds, timeout);
    if (res == -1) {
        if (errno != EINTR) {
            perror("Ошибка во время ожидания события на сокете");
        }
    }
    return res;
}