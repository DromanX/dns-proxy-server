#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/config.h"

#define MAX_LINE_LENGTH 256

// Функция для чтения конфигурационного файла
void readConfig(const char *filename, DnsProxyConfig *config) {
    
    // Открываем файл конфигурации в режиме чтения
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        perror("Ошибка открытия файла конфигурации");
        exit(EXIT_FAILURE);
    }

    // Читаем каждую строку в файле конфигурации
    char line[MAX_LINE_LENGTH];
    while (fgets(line, sizeof(line), file) != NULL) {
        char *key = strtok(line, "=");      // Извлекаем ключ из строки
        char *value = strtok(NULL, "\n");   // Извлекаем значение из строки

        // Пропускаем пустые строки или строки без значения
        if (*key == '\n' || value == NULL)
            continue;
        
        // Сравниваем ключ и сохраняем соответствующее значение в структуру config
        if (strcmp(key, "dns_server_ip") == 0) {
            strncpy(config->upstream_dns_server_ip, value, INET_ADDRSTRLEN);
        } else if (strcmp(key, "blacklist_response_type") == 0) {
            strncpy(config->blacklist_response_type, value, sizeof(config->blacklist_response_type));
        } else if (strcmp(key, "fixed_ip") == 0) {
            strncpy(config->fixed_ip, value, INET_ADDRSTRLEN);
        } else if (strcmp(key, "blacklist") == 0) {
            char *domain = strtok(value, ",");  // Разделяем строку значений доменов черного списка по запятым
            while (domain != NULL) {
                // Увеличиваем размер массива blacklist для добавления в него нового домена
                config->blacklist = realloc(config->blacklist, sizeof(char *) * (++config->blacklist_size));
                if (config->blacklist == NULL) {
                    perror("Невозможно выделить память");
                    exit(EXIT_FAILURE);
                }
                config->blacklist[config->blacklist_size - 1] = strdup(domain); // Копируем домен из строки в структуру config
                domain = strtok(NULL, ",");
            }
        }
    }

    // Закрываем файл
    fclose(file);
}