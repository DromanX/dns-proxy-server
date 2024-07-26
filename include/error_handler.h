#ifndef ERROR_HANDLER
#define ERROR_HANDLER

#include <sys/types.h>
#include <sys/socket.h>
#include <poll.h>

int Socket(int domain, int type, int protocol);

void Bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

void Inet_pton(int af, const char *src, void *dst);

int Recvfrom(int sockfd, void *data, size_t datalen, int flags, struct sockaddr *addr, socklen_t *addrlen);

void Sendto(int sockfd, const void *data, size_t datalen, int flags, const struct sockaddr *addr, socklen_t addrlen);

int Poll(struct pollfd *fds, nfds_t nfds, int timeout);

#endif