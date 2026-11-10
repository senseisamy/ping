#include "ping.h"
#include <stddef.h>
#include <sys/_select.h>
#include <sys/_types/_fd_def.h>
#include <sys/_types/_timeval.h>
#include <sys/time.h>

extern struct argp argp_setup;

ping_stats stats = {0};

void exit_error(char* error_msg) {
    dprintf(STDERR_FILENO, "ft_ping error: %s\n", error_msg);
    exit(1);
}

void print_stats() {
    printf("--- %s ping statistics ---\n", stats.destination); 

    struct timeval end;
    gettimeofday(&end, NULL);
    //size_t time_passed = (end.tv_sec - stats.start.tv_sec) * 1000 + (end.tv_usec - stats.start.tv_usec) / 1000;

    printf(
        "%ld packets transmitted, %ld packets received, %g%% packet loss\n",
        stats.packets_transmitted, stats.packets_received,
        (1.0 - (float)stats.packets_received / (float)stats.packets_transmitted) * 100
    );

    if (stats.packets_received > 0) {
        double avg_rtt = stats.sum_rtt / stats.packets_received;
        double avg_rtt_sq = stats.sum_rtt_sq / stats.packets_received;
        // standard deviation
        double mdev = sqrt(avg_rtt_sq - (avg_rtt * avg_rtt));

        printf(
            "round-trip min/avg/max/stddev = %.3f/%.3f/%.3f/%.3f ms\n",
            stats.min_rtt, avg_rtt, stats.max_rtt, mdev
        );
    }
}

void sigint_handler(int sig_num) {
    (void)sig_num;

    print_stats();

    exit(0);
}

struct timeval usec_to_timeval(size_t usec) {
    struct timeval time = {0};

    time.tv_sec = usec / 1000000;
    time.tv_usec = usec % 1000000;

    return time;
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

void send_packet(char data[64], icmp_header* header, int socket, struct sockaddr_in* ip, struct arguments* args) {
    create_data(data, header);
    if(sendto(socket, data, 64, 0, (struct sockaddr*)ip, sizeof(*ip)) == -1) {
        close(socket);
        exit_error("failed to send packet\n");
    }

    if (args->flood)
        putchar('.');

    stats.packets_transmitted += 1;
}

void receive_reply(int sock, icmp_header* header, struct arguments* args) {
    char recv_buffer[1024];
    struct sockaddr_in sender_addr;
    socklen_t saddr_len = sizeof(sender_addr);

    ssize_t bytes = recvfrom(sock, recv_buffer, sizeof(recv_buffer), 0, (struct sockaddr*)&sender_addr, &saddr_len);

    if (bytes < 0) {
        return;
    }

    // we need to skip the ipv4 header to read the icmp header
    // https://en.wikipedia.org/wiki/IPv4#Header
    size_t ihl = recv_buffer[0] & 0b00001111;
    // ihl counts the number of 32bits words (4 bytes) -> we need to multiply by 4 to have the total number of bytes
    size_t ip_header_length = ihl * 4;

    if ((size_t)bytes < ip_header_length + sizeof(icmp_header))
        return; // the reply is too short to be a icmp message

    icmp_header* icmp = (icmp_header*)&recv_buffer[ip_header_length];

    if (icmp->type != 0)
        return; // not a icmp echo reply
    if (icmp->identifier != header->identifier)
        return; // not the reply to our echo

    stats.packets_received += 1;
    header->sequence += 1;

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

    struct timeval now, next_time_send;
    size_t sleeptime = 1000000; // 1 second
    if (args.flood)
        sleeptime = 10000; // 10 ms
    if (args.interval > 0.0)
        sleeptime = args.interval;

    struct timeval program_timeout = {0};
    if (args.timeout > 0) {
        gettimeofday(&program_timeout, NULL);
        timeradd(&program_timeout, &((struct timeval){.tv_sec = args.timeout, .tv_usec = 0}), &program_timeout);
    }

    gettimeofday(&stats.start, NULL);
    stats.min_rtt = DBL_MAX;

    signal(SIGINT, sigint_handler);

    printf("PING %s (%s) 56 bytes of data.\n", args.destination, args.ip);

    gettimeofday(&next_time_send, NULL); // set to 'now' so we can send immediately

    struct timeval interval = usec_to_timeval(sleeptime);

    bool ping_stop = false;

    while (!ping_stop) {
        gettimeofday(&now, NULL);

        if (args.timeout > 0 && timercmp(&now, &program_timeout, >=)) {
            ping_stop = true;
            continue;
        }

        // STEP 1: SEND IF IT'S TIME
        if (args.preload > 0) {
            send_packet(data, &header, sock, &ip, &args);
            --args.preload;
        } else if (timercmp(&now, &next_time_send, >=)) { // now is the time to send
            send_packet(data, &header, sock, &ip, &args);
            timeradd(&next_time_send, &interval, &next_time_send); // increase the value for the next time to send
        }
        // if (args.preload > 0) {
        //     ++header.sequence;
        //     --args.preload;
        //     continue;
        // }

        // STEP 2: THE WAIT
        struct timeval timeout;
        if (args.preload > 0) {
            timeout.tv_sec = 0;
            timeout.tv_usec = 0;
        } else {
            // timeout = next_time_send - now
            timersub(&next_time_send, &now, &timeout);
        }

        fd_set read_set;
        FD_ZERO(&read_set);
        FD_SET(sock, &read_set);

        int ready = select(sock + 1, &read_set, NULL, NULL, &timeout);

        // STEP 3: RECEIVE
        if (ready && FD_ISSET(sock, &read_set)) {
            // we have a reply
            receive_reply(sock, &header, &args);
        }

    }
    
    print_stats();

    return 0;
}