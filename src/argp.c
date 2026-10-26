#include "ping.h"
#include <string.h>

static char doc[] = "ft_ping -- a simple ping implementation";
static char args_doc[] = "<Destination>";

static struct argp_option options[] = {
  {"verbose", 'v', 0, 0, "Verbose output", 0},
  {"flood", 'f', 0, 0, "Flood ping", 0},
  {0}
};

int valid_ip(char* arg, char ip[INET_ADDRSTRLEN]) {
    struct sockaddr_in a = {0};
    if (inet_pton(AF_INET, arg, &a.sin_addr) != 0) {
        inet_ntop(AF_INET, &a.sin_addr, ip, INET_ADDRSTRLEN);
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

    inet_ntop(AF_INET, &((struct sockaddr_in*)result->ai_addr)->sin_addr, ip, INET_ADDRSTRLEN);
    freeaddrinfo(result);
    return 1;
}

static error_t parse_opt(int key, char* arg, struct argp_state* state) {
    struct arguments* arguments = state->input;

    switch (key) {
        case 'v':
            arguments->verbose = 1;
            break;
        case ARGP_KEY_ARG:
            if (state->arg_num >= 1) // too many arguments
                argp_usage(state);
            if (valid_ip(arg, arguments->ip)) {
                arguments->destination = arg;
                if (strcmp(arguments->destination, arguments->ip))
                    arguments->dns_resolved = 1;
            }
            else
                argp_error(state, "Invalid IP address '%s'", arg);
            break;
        case ARGP_KEY_END:
            if (state->arg_num < 1) // not enough argument
                argp_usage(state);
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

struct argp argp_setup = {options, parse_opt, args_doc, doc, NULL, NULL, NULL};

