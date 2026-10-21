#include "ping.h"

void exit_error(char* error_msg) {
    dprintf(STDERR_FILENO, "ft_ping error: %s\n", error_msg);
    exit(1);
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

void receive_reply(int sock, char data[64], icmp_header* header) {
    char recv_buffer[1024];
    struct sockaddr_in sender_addr;
    socklen_t saddr_len = sizeof(sender_addr);

    // 1 second timeout
    struct timeval timeout = {.tv_sec = 1, .tv_usec = 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    while (1) {
        ssize_t bytes = recvfrom(sock, recv_buffer, sizeof(recv_buffer), 0, (struct sockaddr*)&sender_addr, &saddr_len);

        if (bytes < 0) {
            printf("recv timeout\n");
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

        //TODO: calculate time
        (void)data;

        printf("received a reply!\n");

        break;
    }
}

// usage: ft_ping [options] ip
int main(int ac, char **av) {
    uint32_t options = 0;
    struct sockaddr_in ip;
    char address_str[INET_ADDRSTRLEN];

    parse_argv(ac, av, &options, &ip, address_str);

    printf("ip address: %s\n", address_str);

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0)
        exit_error("socket creation failed, make sure you run the program as root\n");

    icmp_header header = create_icmp_header();
    char data[64];

    while (1) {
        create_data(data, &header);
        
        if(sendto(sock, data, 64, 0, (struct sockaddr*)&ip, sizeof(ip)) == -1) {
            close(sock);
            exit_error("failed to send packet\n");
        }

        printf("succesfully sent packet\n");

        receive_reply(sock, data, &header);

        ++header.sequence;

        sleep(1);
    }
    
    return 0;
}