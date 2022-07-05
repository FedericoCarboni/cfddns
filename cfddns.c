#define _GNU_SOURCE

#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>

struct pcg32_random_ctx {
    uint64_t state;
    uint64_t inc;
};

/*
 * The global RNG state, a RNG is needed for DNS Queries.
 */
static struct pcg32_random_ctx pcg32_random_ctx;

static inline uint64_t random_shuffle(uint64_t x) {
    x ^= x >> 30;
    x *= 0xbf58476d1ce4e5b9UL;
    x ^= x >> 27;
    x *= 0x94d049bb133111ebUL;
    x ^= x >> 31;
    return x;
}

static void pcg32_random_init(void) {
    uint64_t seed = (uint64_t)(uintptr_t)&pcg32_random_init;
    struct timespec time;
    clock_gettime(CLOCK_MONOTONIC, &time);
    seed ^= (uint64_t)time.tv_sec;
    seed ^= (uint64_t)time.tv_nsec;
    uint64_t max = ((seed ^ (seed >> 17)) & 0x0F) + 1;
    for (uint64_t i = 0; i < max; i++) {
        seed = random_shuffle(seed);
    }
    pcg32_random_ctx.state = seed;
    pcg32_random_ctx.inc = random_shuffle(seed) | 1; // inc must be odd
}

static uint32_t pcg32_random(void) {
    uint64_t oldstate = pcg32_random_ctx.state;
    pcg32_random_ctx.state = oldstate * 6364136223846793005ULL + pcg32_random_ctx.inc;
    uint32_t xorshifted = ((oldstate >> 18u) ^ oldstate) >> 27u;
    uint32_t rot = oldstate >> 59u;
    return (xorshifted >> rot) | (xorshifted << ((-rot) & 31));
}

static const uint32_t OPENDNS_SERVERS[4] = {
    0xD043DEDE, // 208.67.222.222 resolver1.opendns.com
    0xD043DCDC, // 208.67.220.220 resolver2.opendns.com
    0xD043DEDC, // 208.67.222.220 resolver3.opendns.com
    0xD043DCDE, // 208.67.220.222 resolver4.opendns.com
};

static unsigned int opendns_index = 0;

static struct sockaddr_in dns_sockaddr;
static int socket_fd;

static void read_dns_name(uint8_t *name, uint8_t *buf, uint8_t *resp, int *count) {
    unsigned int p = 0, jumped = 0, offset;
    int i, j;

    *count = 1;
    name[0] = '\0';

    // read the names in 3www6google3com format
    while (*buf != 0) {
        if (*buf >= 192) {
            offset = (*buf) * 256 + *(buf + 1) - 49152; // 49152 = 11000000 00000000 ;)
            buf = resp + offset - 1;
            jumped = 1; // we have jumped to another location so counting wont go up!
        } else {
            name[p++] = *buf;
        }

        buf = buf + 1;

        if (jumped == 0) {
            *count = *count + 1; // if we havent jumped to another location then we can count up
        }
    }

    name[p] = '\0'; // string complete
    if (jumped == 1) {
        *count = *count + 1; // number of steps we actually moved forward in the packet
    }
}


static int try_find_ip(struct in_addr *addr) {
    uint16_t id = (uint16_t)(pcg32_random() & 0xffffU);
    uint16_t packet[17];
    packet[0] = htons(id);
    packet[1] = htons(1 << 8); // Header flags (bit8 is Recursion Desired)
    packet[2] = htons(1);      // QDCOUNT one question
    packet[3] = 0;             // ANCOUNT
    packet[4] = 0;             // NSCOUNT
    packet[5] = 0;             // ARCOUNT
    // Copy QNAME
    memcpy(&packet[6], "\4myip\7opendns\3com\0", 18);
    packet[15] = htons(1);     // QTYPE, A record
    packet[16] = htons(1);     // QCLASS

    // Get OpenDNS socket address
    // struct sockaddr_in dns_sockaddr;
    // dns_sockaddr.sin_family = AF_INET;
    // dns_sockaddr.sin_port = htons(53);
    // dns_sockaddr.sin_addr.s_addr = htonl(dns_server_ip);

    // Open a socket
    // int socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    ssize_t ret;

    ret = sendto(socket_fd, packet, sizeof(packet), 0,
                 &dns_sockaddr, sizeof(dns_sockaddr));
    if (ret < 0)
        return ret;
    
    uint8_t resp[1 << 12];

    unsigned int socket_address_size = sizeof(dns_sockaddr);
    unsigned int retries = 16;
    do {
        ret = recvfrom(socket_fd, resp, sizeof(resp), 0,
                       &dns_sockaddr, &socket_address_size);
        if (ret < 0)
            return ret;
        if (--retries == 0)
            break;
    } while (ret < sizeof(packet) || ntohs(((uint16_t *)resp)[0]) != id);

    uint16_t ancount = ntohs(((uint16_t *)resp)[3]);
    uint8_t name[256];

    uint8_t *buf = resp + sizeof(packet);

    int count = 0;

    read_dns_name(name, buf, resp, &count);

    buf += count;

    if (!memcmp("\4myip\7opendns\3com\0", name, 18) && ntohs(((uint16_t *)buf)[0]) == 1) {
        addr->s_addr = htonl((buf[10] << 24) | (buf[11] << 16) | (buf[12] << 8) | buf[13]);
        return 0;
    }

    return -1;
}

static int network_init(void) {
    dns_sockaddr.sin_family = AF_INET;
    dns_sockaddr.sin_port = htons(53);
    dns_sockaddr.sin_addr.s_addr = htonl(OPENDNS_SERVERS[0]);

    socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_fd < 0)
        return socket_fd;
    int ret;
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 50000;
    ret = setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (ret < 0)
        return ret;
    return 0;
}

int main(void) {
    pcg32_random_init();
    int ret = network_init();
    if (ret < 0)
        goto error;
    struct in_addr addr;
    ret = try_find_ip(&addr);
    if (ret < 0)
        goto error;
    return 0;
error:
    printf("%s\n", strerror(ret));
    return -ret;
}
