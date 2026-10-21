#include "ping.h"

int valid_ip(char* arg, struct sockaddr_in* ip, char ip_str[INET_ADDRSTRLEN]) {
    struct sockaddr_in a = {0};
    if (inet_pton(AF_INET, arg, &a.sin_addr) != 0) {
        *ip = a;
        inet_ntop(AF_INET, &a.sin_addr, ip_str, INET_ADDRSTRLEN);
        return 1;
    }

    // try dns resolution
    struct addrinfo hints = {0};
    struct addrinfo *result;

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_RAW;
    hints.ai_protocol = IPPROTO_ICMP;

    int status = getaddrinfo(arg, NULL, &hints, &result);

    if (status != 0) {
        return 0;
    }

    *ip = *(struct sockaddr_in*)result->ai_addr;
    inet_ntop(AF_INET, &ip->sin_addr, ip_str, INET_ADDRSTRLEN);
    freeaddrinfo(result);
    return 1;
}

static void parse_option(char* opt, uint32_t* options) {
    for (int i = 1; opt[i]; ++i) {
        switch (opt[i]) {
            case 'v':
                *options |= OPT_VERBOSE;
                break;
            
            default:
                exit_error("unknown option");
        }
    }
}

void parse_argv(int ac, char** av, uint32_t* options, struct sockaddr_in* ip, char ip_str[INET_ADDRSTRLEN]) {
    if (ac < 2)
        exit_error("invalid use: must provide at least one argument");
    if (!av)
        exit_error("arguments are null");

    int address_found = 0;
    
    for (int i = 1; i < ac; ++i) {
        if (!av[i])
            continue;

        if (av[i][0] == '-') { // option
            parse_option(av[i], options);
        } else { // ip address
            if (!address_found) {
                if (!valid_ip(av[i], ip, ip_str))
                    exit_error("invalid ip address");
            }
            address_found = 1;
        }
    }

    if (!address_found)
        exit_error("invalid use: must provide an ip address");
}