#include <stdio.h> // Структура FILE
#include <stdlib.h> // Функция realloc()
#include <unistd.h> // Функция close()

#include "../include/config.h"
#include "../include/dns_proxy.h"

#define CONFIG_FILE "../config/dns_proxy.conf"

int main() {
    DnsProxyConfig config = { 0 };
    readConfig(CONFIG_FILE, &config);
    runServer(&config);

    for (int i = 0; i < config.blacklist_size; i++) {
        free(config.blacklist[i]);
    }
    free(config.blacklist);

    return 0;
}