#include "../include/config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LINE_LENGTH 256

void readConfig(const char *filename, DnsProxyConfig *config) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        perror("Ошибка открытия файла конфигурации");
        exit(EXIT_FAILURE);
    }

    char line[MAX_LINE_LENGTH];
    while (fgets(line, sizeof(line), file) != NULL) {
        char *key = strtok(line, "=");
        char *value = strtok(NULL, "\n");

        if (*key == '\n' || value == NULL)
            continue;

        if (strcmp(key, "dns_server_ip") == 0) {
            strncpy(config->upstream_dns_server_ip, value, INET_ADDRSTRLEN);
        } else if (strcmp(key, "blacklist_response_type") == 0) {
            strncpy(config->blacklist_response_type, value, sizeof(config->blacklist_response_type));
        } else if (strcmp(key, "fixed_ip") == 0) {
            strncpy(config->fixed_ip, value, INET_ADDRSTRLEN);
        } else if (strcmp(key, "blacklist") == 0) {
            char *domain = strtok(value, ",");
            while (domain != NULL) {
                config->blacklist = realloc(config->blacklist, sizeof(char *) * (++config->blacklist_size));
                if (config->blacklist == NULL) {
                    perror("Невозможно выделить память");
                    exit(EXIT_FAILURE);
                }
                config->blacklist[config->blacklist_size - 1] = strdup(domain);
                domain = strtok(NULL, ",");
            }
        }
    }

    fclose(file);
}