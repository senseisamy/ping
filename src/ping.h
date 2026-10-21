#ifndef PING_H
# define PING_H

# include <stddef.h>
# include <stdint.h>
# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <sys/time.h>

# include <netinet/in.h>
# include <arpa/inet.h>
# include <netdb.h>
# include <sys/socket.h>
# include <unistd.h>

# define OPT_VERBOSE (1 << 0)

typedef struct icmp_header {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t identifier;
    uint16_t sequence;
} icmp_header;

void exit_error(char* error_msg);
void parse_argv(int ac, char** av, uint32_t* options, struct sockaddr_in* ip, char ip_str[INET_ADDRSTRLEN]);

#endif