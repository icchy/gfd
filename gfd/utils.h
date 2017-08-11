#ifndef _INCLUDE_UTILS_H
#define _INCLUDE_UTILS_H

#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/skbuff.h>

#define IP_LOCALHOST ((uint32_t)0x0100007f) // 127.0.0.1
#define IP_LOCALHOST_ETH ((uint32_t)0xfe32a8c0) // 192.168.50.254


void *memmem(const void *, size_t, const void *, size_t);
static int load_and_check_header(struct sk_buff *, struct iphdr *, struct tcphdr *, struct udphdr *);
static int calc_csum(struct sk_buff*);

void print_ipaddr(char *, uint32_t);
void hexdump(uint8_t *, size_t);

#endif
