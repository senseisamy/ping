CC = cc
FLAGS = -Wall -Wextra -Werror -g3

BIN = ft_ping
SRC = $(addprefix src/, ping.c argp.c)
OBJ = $(patsubst src/%.c, $(OBJ_DIR)/%.o, $(SRC))

INCLUDE = src/ping.h
OBJ_DIR = obj

all: $(BIN)

$(BIN): $(OBJ_DIR) $(OBJ)
	$(CC) $(FLAGS) $(OBJ) -o $(BIN) -lm

$(OBJ_DIR)/%.o: src/%.c $(INCLUDE)
	$(CC) $(FLAGS) -c -o $@ $<

$(OBJ_DIR):
	@mkdir -p $(OBJ_DIR)

clean:
	rm -rf $(OBJ_DIR)

fclean: clean
	rm -f $(BIN)

re: fclean
	make $(BIN)

.PHONY: all clean fclean re