#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/udp.h>

#include "hook_dns.h"
#include "utils.h"

#define TABLE_SIZE (1<<4)

typedef struct {
  uint32_t saddr;
  uint32_t daddr;
  uint16_t sport;
} ENTRY;

ENTRY table[TABLE_SIZE];
int idx;

static int table_push(struct iphdr *iph, struct udphdr *udph) {
  int start = idx++;

  while(start != (idx&(TABLE_SIZE))) {
    idx &= TABLE_SIZE-1;
    if(!table[idx].sport) {
      table[idx].saddr = iph->saddr;
      table[idx].daddr = iph->daddr;
      table[idx].sport = udph->source;
      return 0;
    }
    ++idx;
  }
  return -1;
}

static uint32_t table_pop(struct iphdr *iph, struct udphdr *udph) {
  int i;

  for(i = 0; i < TABLE_SIZE; ++i) {
    if(table[i].saddr == iph->daddr
        && table[i].daddr == iph->saddr
        && table[i].sport == udph->dest) {
      table[i].sport = 0;
      return table[i].daddr;
    }
  }
}


static unsigned handle_hook_dns_in(const struct nf_hook_ops *ops,
    struct sk_buff *skb,
    const struct net_device *in,
    const struct net_device *out,
    int (*okfn)(struct sk_buff*))
{
  struct iphdr *iph;
  struct udphdr *udph;
  uint32_t saddr;

  if(load_and_check_header(skb, iph, NULL, udph))
    return NF_ACCEPT;

  // allow to localhost
  if(iph->daddr == IP_LOCALHOST || iph->daddr == IP_LOCALHOST_ETH) {
    return NF_ACCEPT;
  }

  // rewrite dest if port 53

  // allow except udp port 53 (DNS)
  if(be16_to_cpu(udph->source) != 53)
    return NF_DROP;

  // overwrite src
  if((saddr = table_pop(iph, udph)) == 0x0) {
    printk(KERN_INFO "GFD: failed to pop udp entry\n");
    return NF_DROP;
  }
  iph->saddr = saddr;
  calc_csum(skb);

  return NF_ACCEPT;
}

static unsigned handle_hook_dns_out(const struct nf_hook_ops *ops,
    struct sk_buff *skb,
    const struct net_device *in,
    const struct net_device *out,
    int (*okfn)(struct sk_buff*))
{
  struct iphdr *iph;
  struct udphdr *udph;


  if(load_and_check_header(skb, iph, NULL, udph))
    return NF_ACCEPT;

  // allow from localhost
  if(iph->saddr == IP_LOCALHOST_ETH || iph->saddr == IP_LOCALHOST) {
    return NF_ACCEPT;
  }

  // allow except udp port 53 (DNS)
  if(be16_to_cpu(udph->dest) != 53)
    return NF_ACCEPT;

  // print_ipaddr("dst_hook src", iph->saddr);
  // print_ipaddr("dst_hook dst", iph->daddr);

  // overwrite dst
  if(table_push(iph, udph)) {
    printk(KERN_INFO "GFD: failed to push udp entry\n");
  }
  csum_replace4(&iph->check, iph->daddr, IP_LOCALHOST_ETH);
  csum_replace4(&udph->check, iph->daddr, IP_LOCALHOST_ETH);
  iph->daddr = IP_LOCALHOST_ETH;

  return NF_ACCEPT;
}
