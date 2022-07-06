#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <curl/curl.h>

#ifndef PREFIX
#define PREFIX "/usr/local"
#endif

#ifdef DEBUG
#define log_debug(args...) syslog(LOG_DEBUG, args)
#else
#define log_debug(args...)
#endif

#define CONFIG_FILENAME PREFIX "/etc/cfddns.conf"

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
  pcg32_random_ctx.state =
      oldstate * 6364136223846793005ULL + pcg32_random_ctx.inc;
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

// Needs to resynchronize the IP with Cloudflare
static bool is_dirty = true;
// The current IP address
static struct in_addr addr = {0};

// Configuration

/*
 * A valid Cloudflare API token to authorize API requests.
 * Required.
 */
static char *cfg_cf_token = NULL;
/*
 * How frequently we should check for IP address changes in seconds.
 */
static unsigned int cfg_interval = 40;

/*
 * A DNS zone with entries that need to be updated.
 */
struct cfg_dns_zone {
  char *zone_id;
  char **id;
  unsigned int len;
};

/*
 * DNS Zones that are configured to be updated.
 * Must contain at least one zone.
 */
static struct cfg_dns_zone *cfg_zones = NULL;
static unsigned int cfg_zones_len = 0;

static int read_dns_name(uint8_t *name, unsigned int name_len, uint8_t *buf,
                         uint8_t *resp) {
  unsigned int p = 0, jumped = 0, offset;

  int count = 1;
  name[0] = '\0';

  // read the names in 3www6google3com format
  while (*buf != 0 && p < name_len - 1) {
    if (*buf >= 192) {
      offset =
          (*buf) * 256 + *(buf + 1) - 49152; // 49152 = 11000000 00000000 ;)
      buf = resp + offset - 1;
      jumped = 1; // we have jumped to another location so counting wont go up!
    } else {
      name[p++] = *buf;
    }

    buf = buf + 1;

    if (jumped == 0) {
      count +=
          1; // if we havent jumped to another location then we can count up
    }
  }

  name[p] = '\0'; // string complete
  if (jumped == 1) {
    count += 1; // number of steps we actually moved forward in the packet
  }
  return count;
}

static int try_find_ip(struct in_addr *addr) {
  // Get a random id for the request
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
  packet[15] = htons(1); // QTYPE, A record
  packet[16] = htons(1); // QCLASS

  dns_sockaddr.sin_addr.s_addr = htonl(OPENDNS_SERVERS[opendns_index]);
  // Always switch OpenDNS servers
  opendns_index = (opendns_index + 1) % 4;

  ssize_t ret;

  ret = sendto(socket_fd, packet, sizeof(packet), 0, &dns_sockaddr,
               sizeof(dns_sockaddr));
  if (ret < 0)
    return ret;

  uint8_t resp[1 << 12];

  unsigned int socket_address_size = sizeof(dns_sockaddr);
  ret = recvfrom(socket_fd, resp, sizeof(resp), 0, &dns_sockaddr,
                 &socket_address_size);
  if (ret < 0)
    return ret;
  if (ret < sizeof(packet) || ntohs(((uint16_t *)resp)[0]) != id) {
    return -1;
  }

  uint8_t *buf = resp + sizeof(packet);

  uint8_t name[18];
  buf += read_dns_name(name, sizeof(name), buf, resp);

  if (!memcmp("\4myip\7opendns\3com\0", name, 18) &&
      ntohs(((uint16_t *)buf)[0]) == 1) {
    addr->s_addr =
        htonl((buf[10] << 24) | (buf[11] << 16) | (buf[12] << 8) | buf[13]);
    return 0;
  }

  return -1;
}

static char *_zone_id;
static char *_record_id;

static void receive_cf_response(void *buffer, size_t size, size_t nmemb,
                                void *userp) {
  // printf("Received response: %s\n", buffer);
  if (strstr((char *)buffer, "\"success\":true") == NULL) {
    is_dirty = true;
    syslog(LOG_ERR,
           "Cloudflare API request failed (Zone %s, DNS Record %s): %s",
           _zone_id, _record_id, (char *)buffer);
  }
  log_debug("Cloudflare update successful (Zone %s, DNS Record %s)", _zone_id,
            _record_id);
}

static int update_dns_record(char *zone_id, char *record_id) {
  _zone_id = zone_id;
  _record_id = record_id;
  CURL *curl = curl_easy_init();

  char url[1024];
  snprintf(url, sizeof(url),
           "https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s",
           zone_id, record_id);

  // Get headers
  char auth_header[512];
  snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s",
           cfg_cf_token);
  struct curl_slist *headers = curl_slist_append(NULL, auth_header);
  headers = curl_slist_append(headers, "Content-Type: application/json");

  char json_payload[512];
  snprintf(json_payload, sizeof(json_payload), "{\"content\":\"%s\"}",
           inet_ntoa(addr));

  log_debug("Sending request to %s, payload: %s, auth: %s\n", url, json_payload,
            auth_header);

  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PATCH");
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_payload);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, receive_cf_response);

  curl_easy_perform(curl);

  curl_easy_cleanup(curl);

  curl_slist_free_all(headers);
  return 0;
}

static int try_update_check(void) {
  struct in_addr new_addr;
  int ret = try_find_ip(&new_addr);
  if (ret < 0) {
    log_debug("Failed to find new IP address.");
    return ret;
  }
  if (is_dirty || new_addr.s_addr != addr.s_addr) {
    addr = new_addr;
    log_debug("Found new IP address: %s.", inet_ntoa(addr));
    for (unsigned int i = 0; i < cfg_zones_len; i++) {
      for (unsigned int j = 0; j < cfg_zones[i].len; j++) {
        ret = update_dns_record(cfg_zones[i].zone_id, cfg_zones[i].id[j]);
        if (ret < 0) {
          is_dirty = true;
          return ret;
        }
      }
    }
    printf("IP address updated to %s\n", inet_ntoa(addr));
    is_dirty = false;
  } else {
    log_debug("IP address didn't change.");
  }
  return 0;
}

static void update_check(void) {
  int ret = try_update_check();
  if (ret < 0)
    log_debug("Update failed: %s", strerror(ret));

  // Schedule the next update check
  alarm(cfg_interval);
}

static int dns_init(void) {
  dns_sockaddr.sin_family = AF_INET;
  dns_sockaddr.sin_port = htons(53);

  log_debug("Opening a UDP socket");
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
  log_debug("Successfully opened UDP socket: %i", socket_fd);
  return 0;
}

static void deinit(void) {
  log_debug("Deallocating memory");

  free(cfg_cf_token);
  if (cfg_zones != NULL) {
    for (unsigned int i = 0; i < cfg_zones_len; i++) {
      for (unsigned int j = 0; j < cfg_zones[i].len; j++) {
        free(cfg_zones[i].id[j]);
      }
      free(cfg_zones[i].zone_id);
      free(cfg_zones[i].id);
    }
  }
  free(cfg_zones);

  log_debug("Closing open sockets");
  close(socket_fd);
  curl_global_cleanup();
  closelog();
}

static void print_config_file_help(void) {
  printf(
    "Invalid or missing config file, please edit " CONFIG_FILENAME " to include a valid cf_token, zone_id and id.\n\n"
    "The config file consists of key=value pairs, empty lines are ignored.\n"
    "  'cf_token' is required and must be set to a valid Cloudflare API token.\n"
    "  'interval' specifies how frequently the daemon should check for IP changes, in seconds. Defaults to 40.\n"
    "  'zone_id' sets the id of the Cloudflare DNS zone to update, it must precede any id key. It can be repeated multiple times to update multiple DNS zones.\n"
    "  'id' sets the id of the Cloudflare DNS record to update. It can be repeated multiple times to update multiple DNS records.\n"
  );
}

static int parse_config(void) {
  // Open config in readonly mode
  FILE *config = fopen(CONFIG_FILENAME, "r");
  if (config == NULL) {
    return -1;
  }
  struct cfg_dns_zone *zone;
  char key[255];
  char value[255];
  int ret = 0;
  while (1) {
    ret = fscanf(config, "\n%[^=]254s", key);
    if (ret < 0) {
      break;
    }
    ret = fscanf(config, "=%[^\n]254s", value);
    if (ret < 0) {
      break;
    }
    if (!strcmp("cf_token", key)) {
      if (cfg_cf_token != NULL) {
        printf("Duplicate key cf_token in configuration file");
        return -1;
      }
      cfg_cf_token = strdup(value);
    } else if (!strcmp("interval", key)) {
      cfg_interval = (unsigned int)atol(value);
    } else if (!strcmp("zone_id", key)) {
      cfg_zones_len += 1;
      if (cfg_zones != NULL) {
        cfg_zones =
            realloc(cfg_zones, cfg_zones_len * sizeof(struct cfg_dns_zone));
      } else {
        cfg_zones = malloc(cfg_zones_len * sizeof(struct cfg_dns_zone));
      }
      zone = &cfg_zones[cfg_zones_len - 1];
      zone->zone_id = strdup(value);
      zone->id = NULL;
      zone->len = 0;
    } else if (!strcmp("id", key)) {
      if (zone == NULL) {
        return -1;
      }
      zone->len += 1;
      if (zone->id != NULL) {
        zone->id = realloc(zone->id, zone->len * sizeof(char *));
      } else {
        zone->id = malloc(zone->len * sizeof(char *));
      }
      zone->id[zone->len - 1] = strdup(value);
    } else {
      log_debug("Unknown config key %s=%s", key, value);
    }
  }
  fclose(config);
  if (cfg_cf_token == NULL)
    printf("'cf_token' was not specified but it is required.\n");
  if (cfg_zones_len < 1 || cfg_zones[0].len < 1)
    printf("Config file must specify at least one DNS zone and record to update.\n");
  if (cfg_cf_token == NULL || cfg_zones_len < 1 || cfg_zones[0].len < 1) {
    printf("\n");
    return -1;
  }
  return 0;
}

static void init(void) {
  int ret;
  // Open system log file
  openlog(NULL, LOG_CONS | LOG_PID, 0);

  ret = parse_config();
  if (ret < 0) {
    print_config_file_help();
    log_debug("Could not parse config file: %s.", strerror(ret));
    deinit();
    exit(1);
  }

  // If we are the root, drop all privileges
  if (getuid() == 0) {
    struct passwd *nobody = getpwnam("nobody");
    if (nobody == NULL || setgid(nobody->pw_gid) < 0 ||
        setuid(nobody->pw_uid) < 0) {
      log_debug("Unable to set user to nobody.");
      deinit();
      exit(1);
    }
  }

  // Initialize the RNG
  pcg32_random_init();

  ret = dns_init();
  if (ret < 0) {
    syslog(LOG_ERR, "Could not open UDP socket for DNS Queries: %s.",
           strerror(ret));
    deinit();
    exit(1);
  }

  // Init curl
  if (curl_global_init(0) != CURLE_OK) {
    syslog(LOG_ERR, "Could not initialize cURL: %s.", curl_easy_strerror(ret));
    deinit();
    exit(1);
  }

  log_debug("Initialization successful.");
}

static void on_alarm(int _) {
  log_debug("Periodic update check");
  update_check();
}

static void on_sigint_sigterm(int signum) {
  syslog(LOG_INFO, "Caught signal %s, exiting...",
         signum == SIGINT ? "SIGINT" : "SIGTERM");
  deinit();
  exit(0);
}

int main(void) {
  init();

  signal(SIGINT, on_sigint_sigterm);
  signal(SIGTERM, on_sigint_sigterm);
  signal(SIGALRM, on_alarm);

  update_check();

  while (1) {
    pause();
  }
}
