#define _GNU_SOURCE

#include <netinet/in.h>

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
unsigned char *ReadName(unsigned char *, unsigned char *, int *);

#define T_A 1     // Ipv4 address
#define T_NS 2    // Nameserver
#define T_CNAME 5 // canonical name
#define T_SOA 6   /* start of authority zone */
#define T_PTR 12  /* domain name pointer */
#define T_MX 15   // Mail server

// DNS header structure
struct DNS_HEADER
{
    unsigned short id; // identification number

    unsigned char rd : 1;     // recursion desired
    unsigned char tc : 1;     // truncated message
    unsigned char aa : 1;     // authoritive answer
    unsigned char opcode : 4; // purpose of message
    unsigned char qr : 1;     // query/response flag

    unsigned char rcode : 4; // response code
    unsigned char cd : 1;    // checking disabled
    unsigned char ad : 1;    // authenticated data
    unsigned char z : 1;     // its z! reserved
    unsigned char ra : 1;    // recursion available

    unsigned short qdcount; // number of question entries
    unsigned short ancount; // number of answer entries
    unsigned short nscount; // number of authority entries
    unsigned short arcount; // number of resource entries
};

// Constant sized fields of query structure
struct QUESTION
{
    unsigned short qtype;
    unsigned short qclass;
};

// Constant sized fields of the resource record structure
#pragma pack(push, 1)
struct R_DATA
{
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
};
#pragma pack(pop)

// Pointers to resource record contents
struct RES_RECORD
{
    unsigned char *name;
    struct R_DATA *resource;
    unsigned char *rdata;
};

// Structure of a Query
typedef struct
{
    unsigned char *name;
    struct QUESTION *ques;
} QUERY;


static int resolve_current_ip(uint32_t dns_server_ip) {
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
    struct sockaddr_in dns_sockaddr;
    dns_sockaddr.sin_family = AF_INET;
    dns_sockaddr.sin_port = htons(53);
    dns_sockaddr.sin_addr.s_addr = htonl(dns_server_ip);

    int socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    ssize_t ret = sendto(socket_fd, packet, sizeof(packet), 0,
                         &dns_sockaddr, sizeof(dns_sockaddr));
    if (ret < 0)
        return ret;
    
    uint8_t buffer[1 << 16];
    unsigned int x = sizeof(dns_sockaddr);
    ret = recvfrom(socket_fd, buffer, sizeof(buffer), 0,
                   &dns_sockaddr, &x);
    if (ret < 0)
        return ret;
    
    char *reader;
    struct DNS_HEADER *dns = NULL;
    struct QUESTION *qinfo = NULL;

    struct RES_RECORD answers[20], auth[20], addit[20]; // the replies from the DNS server

    dns = (struct DNS_HEADER *)buffer;

    // move ahead of the dns header and the query field
    reader = &buffer[sizeof(struct DNS_HEADER) + 18 + sizeof(struct QUESTION)];
    struct sockaddr_in a;

    printf("\nThe response contains : ");
    printf("\n %d Questions.", ntohs(dns->qdcount));
    printf("\n %d Answers.", ntohs(dns->ancount));
    printf("\n %d Authoritative Servers.", ntohs(dns->nscount));
    printf("\n %d Additional records.\n\n", ntohs(dns->arcount));

    // Start reading answers
    int stop = 0;
    int i, j, s;

    for (i = 0; i < ntohs(dns->ancount); i++)
    {
        answers[i].name = ReadName(reader, buffer, &stop);
        reader = reader + stop;

        answers[i].resource = (struct R_DATA *)(reader);
        reader = reader + sizeof(struct R_DATA);

        if (ntohs(answers[i].resource->type) == 1) // if its an ipv4 address
        {
            answers[i].rdata = (unsigned char *)malloc(ntohs(answers[i].resource->data_len));

            for (j = 0; j < ntohs(answers[i].resource->data_len); j++)
            {
                answers[i].rdata[j] = reader[j];
            }

            answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';

            reader = reader + ntohs(answers[i].resource->data_len);
        }
        else
        {
            answers[i].rdata = ReadName(reader, buffer, &stop);
            reader = reader + stop;
        }
    }

    // read authorities
    for (i = 0; i < ntohs(dns->nscount); i++)
    {
        auth[i].name = ReadName(reader, buffer, &stop);
        reader += stop;

        auth[i].resource = (struct R_DATA *)(reader);
        reader += sizeof(struct R_DATA);

        auth[i].rdata = ReadName(reader, buffer, &stop);
        reader += stop;
    }

    // read additional
    for (i = 0; i < ntohs(dns->arcount); i++)
    {
        addit[i].name = ReadName(reader, buffer, &stop);
        reader += stop;

        addit[i].resource = (struct R_DATA *)(reader);
        reader += sizeof(struct R_DATA);

        if (ntohs(addit[i].resource->type) == 1)
        {
            addit[i].rdata = (unsigned char *)malloc(ntohs(addit[i].resource->data_len));
            for (j = 0; j < ntohs(addit[i].resource->data_len); j++)
                addit[i].rdata[j] = reader[j];

            addit[i].rdata[ntohs(addit[i].resource->data_len)] = '\0';
            reader += ntohs(addit[i].resource->data_len);
        }
        else
        {
            addit[i].rdata = ReadName(reader, buffer, &stop);
            reader += stop;
        }
    }

    // print answers
    printf("\nAnswer Records : %d \n", ntohs(dns->ancount));
    for (i = 0; i < ntohs(dns->ancount); i++)
    {
        printf("Name : %s ", answers[i].name);

        if (ntohs(answers[i].resource->type) == T_A) // IPv4 address
        {
            long *p;
            p = (long *)answers[i].rdata;
            a.sin_addr.s_addr = (*p); // working without ntohl
            printf("has IPv4 address : %s", inet_ntoa(a.sin_addr));
        }

        if (ntohs(answers[i].resource->type) == 5)
        {
            // Canonical name for an alias
            printf("has alias name : %s", answers[i].rdata);
        }

        printf("\n");
    }

    // print authorities
    printf("\nAuthoritive Records : %d \n", ntohs(dns->nscount));
    for (i = 0; i < ntohs(dns->nscount); i++)
    {

        printf("Name : %s ", auth[i].name);
        if (ntohs(auth[i].resource->type) == 2)
        {
            printf("has nameserver : %s", auth[i].rdata);
        }
        printf("\n");
    }

    // print additional resource records
    printf("\nAdditional Records : %d \n", ntohs(dns->arcount));
    for (i = 0; i < ntohs(dns->arcount); i++)
    {
        printf("Name : %s ", addit[i].name);
        if (ntohs(addit[i].resource->type) == 1)
        {
            long *p;
            p = (long *)addit[i].rdata;
            a.sin_addr.s_addr = (*p);
            printf("has IPv4 address : %s", inet_ntoa(a.sin_addr));
        }
        printf("\n");
    }
    return;

}

unsigned char *ReadName(unsigned char *reader, unsigned char *buffer, int *count)
{
    unsigned char *name;
    unsigned int p = 0, jumped = 0, offset;
    int i, j;

    *count = 1;
    name = (unsigned char *)malloc(256);

    name[0] = '\0';

    // read the names in 3www6google3com format
    while (*reader != 0)
    {
        if (*reader >= 192)
        {
            offset = (*reader) * 256 + *(reader + 1) - 49152; // 49152 = 11000000 00000000 ;)
            reader = buffer + offset - 1;
            jumped = 1; // we have jumped to another location so counting wont go up!
        }
        else
        {
            name[p++] = *reader;
        }

        reader = reader + 1;

        if (jumped == 0)
        {
            *count = *count + 1; // if we havent jumped to another location then we can count up
        }
    }

    name[p] = '\0'; // string complete
    if (jumped == 1)
    {
        *count = *count + 1; // number of steps we actually moved forward in the packet
    }

    // now convert 3www6google3com0 to www.google.com
    for (i = 0; i < (int)strlen((const char *)name); i++)
    {
        p = name[i];
        for (j = 0; j < (int)p; j++)
        {
            name[i] = name[i + 1];
            i = i + 1;
        }
        name[i] = '.';
    }
    name[i - 1] = '\0'; // remove the last dot
    return name;
}

int main(void) {
    pcg32_random_init();
    printf("%s\n", strerror(resolve_current_ip(OPENDNS_SERVERS[0])));
}
