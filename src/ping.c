#include "ping.h"

extern struct argp argp_setup;

ping_stats stats = {0};

void exit_error(char* error_msg) {
    dprintf(STDERR_FILENO, "ft_ping error: %s\n", error_msg);
    exit(1);
}

void sigint_handler(int sig_num) {
    (void)sig_num;

    printf("--- %s ping statistics ---\n", stats.destination); 

    struct timeval end;
    gettimeofday(&end, NULL);
    size_t time_passed = (end.tv_sec - stats.start.tv_sec) * 1000 + (end.tv_usec - stats.start.tv_usec) / 1000;

    printf(
        "%ld packets transmitted, %ld packets received, %g%% packet loss, time %ldms\n",
        stats.packets_transmitted, stats.packets_received,
        (1.0 - (float)stats.packets_received / (float)stats.packets_transmitted) * 100,
        time_passed
    );

    if (stats.packets_received > 0) {
        double avg_rtt = stats.sum_rtt / stats.packets_received;
        double avg_rtt_sq = stats.sum_rtt_sq / stats.packets_received;
        // standard deviation
        double mdev = sqrt(avg_rtt_sq - (avg_rtt * avg_rtt));

        printf(
            "rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms\n",
            stats.min_rtt, avg_rtt, stats.max_rtt, mdev
        );
    }

    exit(0);
}

void update_stats(double rtt) {
    stats.sum_rtt += rtt;
    stats.sum_rtt_sq += (rtt * rtt);

    if (rtt > stats.max_rtt)
        stats.max_rtt = rtt;

    if (rtt < stats.min_rtt)
        stats.min_rtt = rtt;
}

// RFC 792
icmp_header create_icmp_header() {
    icmp_header header = {0};

    header.type = 8; // echo
    header.code = 0;
    header.checksum = 0; // will be set after
    header.identifier = getpid(); // current pid
    header.sequence = 0; // this increments with every echo

    return header;
}

// 16-bit one's complement of the one's complement sum
// see RFC 792
uint16_t calculate_checksum(char* data) {
    uint32_t sum = 0;
    
    uint16_t* buffer = (uint16_t*)data;

    // sum up all 16-bit words
    for (int i = 0; i < 32; ++i)
        sum += buffer[i];
    
    // fold the 32-bit sum back into 16 bits
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16); // Add any carry
    
    // return the one's complement
    return (uint16_t)(~sum);
}

// The data sent with an imcp echo.
// It first contains the imcp header then some data that can be anything as long
// as the target machine sends the same data back
// The GNU inetutils sends the current time and some padding to use 64 bytes in
// total include the header
void create_data(char data[64], icmp_header* header) {
    // write the icmp header
    memcpy(data, header, sizeof(*header));

    // write the current time
    struct timeval current_time;
    if (gettimeofday(&current_time, NULL) == -1) {
        exit_error("failed to call gettimeofday()");
    }
    memcpy(data + sizeof(*header), &current_time, sizeof(current_time));

    // fill the remaining space with sequential padding
    size_t current_offset = sizeof(*header) + sizeof(current_time);
    for (size_t i = current_offset; i < 64; ++i) {
        data[i] = (char)(i - current_offset); // 0, 1, 2, 3...
    }

    // set checksum
    icmp_header* data_p = (struct icmp_header*)data;
    data_p->checksum = calculate_checksum(data);
}

void receive_reply(int sock, icmp_header* header, struct arguments* args) {
    char recv_buffer[1024];
    struct sockaddr_in sender_addr;
    socklen_t saddr_len = sizeof(sender_addr);

    // 1 second timeout
    struct timeval timeout = {.tv_sec = 1, .tv_usec = 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    while (1) {
        ssize_t bytes = recvfrom(sock, recv_buffer, sizeof(recv_buffer), 0, (struct sockaddr*)&sender_addr, &saddr_len);

        if (bytes < 0) {
            break;
        }

        // we need to skip the ipv4 header to read the icmp header
        // https://en.wikipedia.org/wiki/IPv4#Header
        size_t ihl = recv_buffer[0] & 0b00001111;
        // ihl counts the number of 32bits words (4 bytes) -> we need to multiply by 4 to have the total number of bytes
        size_t ip_header_length = ihl * 4;

        if ((size_t)bytes < ip_header_length + sizeof(icmp_header))
            continue;

        icmp_header* icmp = (icmp_header*)&recv_buffer[ip_header_length];

        if (icmp->type != 0) // not a icmp echo reply
            continue;
        if (icmp->identifier != header->identifier) // not the reply to our echo
            continue;

        stats.packets_received += 1;

        // calculate time
        // the timestamp is located after the ICMP header
        struct timeval* sent_time = (struct timeval*)(recv_buffer + ip_header_length + sizeof(icmp_header));
        struct timeval receive_time;
        gettimeofday(&receive_time, NULL);
        double rtt = (receive_time.tv_sec - sent_time->tv_sec) * 1000.0 + (receive_time.tv_usec - sent_time->tv_usec) / 1000.0;

        update_stats(rtt);

        uint8_t ttl = recv_buffer[8];

        if (args->flood)
            putchar('\b');
        else if (args->dns_resolved)
            printf("64 bytes from %s (%s): icmp_seq=%d ttl=%d time=%.2f ms\n", args->destination, args->ip, icmp->sequence, ttl, rtt);
        else
            printf("64 bytes from %s: icmp_seq=%d ttl=%d time=%.2f ms\n", args->destination, icmp->sequence, ttl, rtt);

        break;
    }
}

// usage: ft_ping [options] ip
int main(int ac, char **av) {
    struct sockaddr_in ip = {0};

    struct arguments args = {0};
    argp_parse(&argp_setup, ac, av, 0, 0, &args);

    stats.destination = args.destination;

    ip.sin_family = AF_INET;
    inet_pton(AF_INET, args.ip, &ip.sin_addr);

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0)
        exit_error("socket creation failed, make sure you run the program as root\n");

    icmp_header header = create_icmp_header();
    char data[64];

    struct timeval start, end;
    size_t sleeptime = 1000000; // 1 000 000 microseconds = 1 second
    if (args.flood)
        sleeptime = 0;
    if (args.interval > 0.0)
        sleeptime = args.interval;

    gettimeofday(&stats.start, NULL);
    stats.min_rtt = DBL_MAX;

    signal(SIGINT, sigint_handler);

    printf("PING %s (%s) 56 bytes of data.\n", args.destination, args.ip);

    while (1) {
        create_data(data, &header);
        
        if(sendto(sock, data, 64, 0, (struct sockaddr*)&ip, sizeof(ip)) == -1) {
            close(sock);
            exit_error("failed to send packet\n");
        }

        if (args.flood)
            putchar('.');

        stats.packets_transmitted += 1;

        gettimeofday(&start, NULL);

        receive_reply(sock, &header, &args);

        gettimeofday(&end, NULL);

        size_t elapsed_time = (end.tv_sec * 1000000 + end.tv_usec) - (start.tv_sec * 1000000 + start.tv_usec);

        if (elapsed_time < sleeptime)
            usleep(sleeptime - elapsed_time);

        ++header.sequence;
    }
    
    return 0;
}