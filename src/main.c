#include <stdlib.h> 

#include "../include/config.h"
#include "../include/dns_proxy.h"

#define CONFIG_FILE "../config/dns_proxy.conf"

int main() {
    DnsProxyConfig config = { 0 };
    readConfig(CONFIG_FILE, &config); // Читаем файл конфигурации и значения копируем в стуктуру config
    runServer(&config);               // Запускаем сервер

    // Освобождение всей выделенной памяти
    for (int i = 0; i < config.blacklist_size; i++) {
        free(config.blacklist[i]);
    }
    free(config.blacklist);

    return 0;
}