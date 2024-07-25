CC = gcc
CFLAGS = -c -W -Wall -Wextra -pedantic -Werror

PREF_BIN_SERVER = ./bin/
PREF_BUILD_SERVER = ./build/
PREF_SRC_SERVER = ./src/

SRC = $(wildcard $(PREF_SRC_SERVER)*.c)
OBJ = $(patsubst $(PREF_SRC_SERVER)%.c, $(PREF_BUILD_SERVER)%.o, $(SRC))
TARGET = $(PREF_BIN_SERVER)server

$(TARGET): $(OBJ)
	mkdir -p $(PREF_BIN_SERVER)
	$(CC) $(OBJ) -o $@

$(PREF_BUILD_SERVER)%.o: $(PREF_SRC_SERVER)%.c
	mkdir -p $(PREF_BUILD_SERVER)
	$(CC) $(CFLAGS) $< -o $@