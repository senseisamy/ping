#ifndef PING_H
# define PING_H

# include <stddef.h>
# include <stdint.h>
# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <sys/time.h>
# include <unistd.h>
# include <signal.h>
# include <float.h>
# include <math.h>
# include <stdbool.h>

# include <netinet/in.h>
# include <arpa/inet.h>
# include <netdb.h>
# include <sys/socket.h>

# include <argp.h>

# define OPT_VERBOSE (1 << 0)

struct arguments {
    bool verbose;
    char* destination;
    char ip[INET_ADDRSTRLEN]; // after domain resolution
    int dns_resolved;
    size_t interval;
    bool flood;
};

typedef struct icmp_header {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t identifier;
    uint16_t sequence;
} icmp_header;

typedef struct ping_stats {
    char* destination;
    size_t packets_transmitted, packets_received;
    struct timeval start;
    double min_rtt, max_rtt, sum_rtt, sum_rtt_sq;
} ping_stats;

void exit_error(char* error_msg);
void parse_argv(int ac, char** av, uint32_t* options, struct sockaddr_in* ip, char ip_str[INET_ADDRSTRLEN]);

#endif