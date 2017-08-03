#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/string.h>


MODULE_AUTHOR("Ryo ICHIKAWA");
MODULE_DESCRIPTION("Great firewall daemon");
MODULE_VERSION("0.1");

#define TABLE_SIZE (1<<4)


typedef struct {
  uint8_t protocol;
  uint32_t saddr;
  uint32_t daddr;
  uint16_t sport;
  uint16_t dport;
} ENTRY;

ENTRY table[TABLE_SIZE];
int idx;


const uint32_t localhost_eth = 0xfe01000a; // 10.0.1.254
const uint32_t localhost = 0x0100007f; // 127.0.0.1


void *memmem(const void* haystack, size_t haystacklen, 
    const void* needle, size_t needlelen)
{
  int i;
  if (needlelen>haystacklen) return 0;
  for(i = 0; i < haystacklen-needlelen; ++i) {
    if(!memcmp(haystack, needle, needlelen))
      return (uint8_t *)haystack;
    ++haystack;
  }
  return 0;
}

void print_ipaddr(char *msg, uint32_t ipaddr) {
  int i, off = 0;
  char buf[64];
  for(i = 0; i < 4; i++) {
    off += snprintf(&buf[off], 4, "%d", ((uint32_t)ipaddr>>(i*8))&0xff);
    if(i < 3) {
      buf[off] = '.';
      off++;
    }
  }
  printk(KERN_INFO "GFD: %s: %s\n", msg, buf);
}

void hexdump(uint8_t *buf, size_t size) {
  printk(KERN_INFO "size: %d\n", size);
  if(size >= 1024) return;
  int i, off = 0;
  char out[1024];
  for(i = 0; i < size; i++) {
    off += snprintf(&out[off], 3, "%02x", buf[i]);
  }
  out[off] = '\0';
  printk(KERN_INFO "dump: %s\n", out);
}

static inline int table_push(struct sk_buff *skb) {
  struct iphdr *iph;
  struct tcphdr *tcph;
  struct udphdr *udph;
  uint16_t sport, dport;
  int start = idx++;

  if((iph = ip_hdr(skb)) == NULL)
    return -1;

  if(iph->protocol == IPPROTO_TCP) {
    if((tcph = tcp_hdr(skb)) == NULL)
      return -1;
    sport = tcph->source;
    dport = tcph->dest;
  } else if(iph->protocol == IPPROTO_UDP) {
    if((udph = udp_hdr(skb)) == NULL)
      return -1;
    sport = udph->source;
    dport = udph->dest;
  } else {
    return -1;
  }

  while(start != (idx&(TABLE_SIZE-1))) {
    idx &= (TABLE_SIZE-1);
    if(!table[idx].sport && !table[idx].dport) {
      table[idx].protocol = iph->protocol;
      table[idx].saddr = iph->saddr;
      table[idx].daddr = iph->daddr;
      table[idx].sport = sport;
      table[idx].dport = dport;
      return 0;
    }
    idx++;
  }
  return -1;
}

static inline uint32_t table_pop(struct sk_buff *skb) {
  struct iphdr *iph;
  struct tcphdr *tcph;
  struct udphdr *udph;
  uint16_t sport, dport;
  int i;

  if((iph = ip_hdr(skb)) == NULL)
    return 0;

  if(iph->protocol == IPPROTO_TCP) {
    if((tcph = tcp_hdr(skb)) == NULL)
      return 0;
    sport = tcph->source;
    dport = tcph->dest;
  } else if(iph->protocol == IPPROTO_UDP) {
    if((udph = udp_hdr(skb)) == NULL)
      return 0;
    sport = udph->source;
    dport = udph->dest;
  } else {
    return 0;
  }

  for(i = 0; i < TABLE_SIZE; ++i) {
    if((table[i].protocol == iph->protocol
        && table[i].saddr == iph->daddr 
        && (iph->protocol == IPPROTO_UDP 
          || table[i].daddr == iph->saddr)
        && table[i].sport == dport
        && table[i].dport == sport)) {
      table[i].sport = 0;
      table[i].dport = 0;
      return table[i].daddr;
    }
  }
  return 0;
}


static unsigned handle_hook_src(const struct nf_hook_ops *ops,
    struct sk_buff *skb,
    const struct net_device *in,
    const struct net_device *out,
    int (*okfn)(struct sk_buff*))
{
  struct iphdr *iph;
  struct tcphdr *tcph;
  struct udphdr *udph;

  uint8_t *tcpdata;
  uint32_t tcpdatalen, tcphlen;
  uint32_t saddr;

  // load ip header
  if((iph = ip_hdr(skb)) == NULL)
    return NF_ACCEPT;

  // allow except IPv4
  if(iph->version != 4)
    return NF_ACCEPT;

  // allow to localhost
  if(iph->daddr == localhost_eth || iph->daddr == localhost) {
    return NF_ACCEPT;
  }

  if(iph->protocol == IPPROTO_TCP && (tcph = tcp_hdr(skb))) {
    // check if packet includes "ictsc"

    tcphlen = ntohs(iph->tot_len) - iph->ihl*4;
    tcpdata = (uint8_t *)tcph + tcph->doff*4;
    tcpdatalen = tcphlen - tcph->doff*4;

    if(table_pop(skb)) {
      printk(KERN_INFO "fuga\n");

      // rewrite RST flag
      tcph->rst = 1;
      tcph->check = 0;
      tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
                                      tcphlen,
                                      iph->protocol,
                                      csum_partial(tcph, tcphlen, 0));
      skb->ip_summed = CHECKSUM_COMPLETE;
      return NF_ACCEPT;
    }

    if(memmem(tcpdata, tcpdatalen, "ictsc", 5) != NULL) {
      if(table_push(skb)) {
        printk(KERN_INFO "GFD: failed to push tcp entry\n");
      }
      // rewrite RST flag
      tcph->rst = 1;
      tcph->check = 0;
      tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
                                      tcphlen,
                                      iph->protocol,
                                      csum_partial(tcph, tcphlen, 0));
      skb->ip_summed = CHECKSUM_COMPLETE;
    }
  }

  if(iph->protocol == IPPROTO_UDP && (udph = udp_hdr(skb))) {
    // rewrite dest if port 53

    // allow except udp port 53 (DNS)
    if(be16_to_cpu(udph->source) != 53)
      return NF_ACCEPT;

    // print_ipaddr("src_hook src", iph->saddr);
    // print_ipaddr("src_hook dst", iph->daddr);

    // overwrite src
    if((saddr = table_pop(skb)) == 0x0) {
      printk(KERN_INFO "GFD: failed to pop udp entry\n");
      return NF_ACCEPT;
    }
    iph->saddr = saddr;
    iph->check = 0;
    iph->check = ip_fast_csum(iph, iph->ihl);
    udph->check = 0;
    udph->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
                                    ntohs(udph->len),
                                    iph->protocol,
                                    csum_partial(udph, ntohs(udph->len), 0));
    skb->ip_summed = CHECKSUM_COMPLETE;
  }

  return NF_ACCEPT;
}

static unsigned handle_hook_dst(const struct nf_hook_ops *ops,
    struct sk_buff *skb,
    const struct net_device *in,
    const struct net_device *out,
    int (*okfn)(struct sk_buff*))
{
  struct iphdr *iph;
  struct tcphdr *tcph;
  struct udphdr *udph;

  uint8_t *tcpdata;
  uint32_t tcpdatalen, tcphlen;

  // load ip header
  if((iph = ip_hdr(skb)) == NULL)
    return NF_ACCEPT;

  // allow except IPv4
  if(iph->version != 4)
    return NF_ACCEPT;

  // allow from localhost
  if(iph->saddr == localhost_eth || iph->saddr == localhost) {
    return NF_ACCEPT;
  }

  if(iph->protocol == IPPROTO_TCP && (tcph = tcp_hdr(skb))) {
    // check if packet includes "ictsc"

    tcphlen = ntohs(iph->tot_len) - iph->ihl*4;
    tcpdata = (uint8_t *)tcph + tcph->doff*4;
    tcpdatalen = tcphlen - tcph->doff*4;

    if(table_pop(skb)) {
      printk(KERN_INFO "fuga\n");
      // rewrite RST flag
      tcph->rst = 1;
      tcph->check = 0;
      tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
                                      tcphlen,
                                      iph->protocol,
                                      csum_partial(tcph, tcphlen, 0));
      skb->ip_summed = CHECKSUM_COMPLETE;
      return NF_ACCEPT;
    }

    if(memmem(tcpdata, tcpdatalen, "ictsc", 5) != NULL) {
      if(table_push(skb)) {
        printk(KERN_INFO "GFD: failed to push tcp entry\n");
      }
      // rewrite RST flag
      tcph->rst = 1;
      tcph->check = 0;
      tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
                                      tcphlen,
                                      iph->protocol,
                                      csum_partial(tcph, tcphlen, 0));
      skb->ip_summed = CHECKSUM_COMPLETE;
    }
  }

  if(iph->protocol == IPPROTO_UDP && (udph = udp_hdr(skb))) {
    // allow except udp port 53 (DNS)
    if(be16_to_cpu(udph->dest) != 53)
      return NF_ACCEPT;

    // print_ipaddr("dst_hook src", iph->saddr);
    // print_ipaddr("dst_hook dst", iph->daddr);

    // overwrite dst
    if(table_push(skb)) {
      printk(KERN_INFO "GFD: failed to push udp entry\n");
    }
    csum_replace4(&iph->check, iph->daddr, localhost_eth);
    csum_replace4(&udph->check, iph->daddr, localhost_eth);
    iph->daddr = localhost_eth;
  }

  return NF_ACCEPT;
}


static struct nf_hook_ops hook_src = {
  .hook = handle_hook_src,
  .pf = PF_INET,
  .hooknum = NF_INET_LOCAL_OUT,
  .priority = NF_IP_PRI_FILTER,
};

static struct nf_hook_ops hook_dst = {
  .hook = handle_hook_dst,
  .pf = PF_INET,
  .hooknum = NF_INET_PRE_ROUTING,
  .priority = NF_IP_PRI_FILTER,
};


int init_module()
{
  int err;

  // init table
  for(idx = 0; idx < TABLE_SIZE; ++idx)
    table[idx].sport = 0;
  idx = 0;

  if((err = nf_register_hook(&hook_src)) < 0) {
    return err;
  }

  if((err = nf_register_hook(&hook_dst)) < 0) {
    return err;
  }

  printk(KERN_INFO "GFD: loaded\n");

  return 0;
}


void cleanup_module()
{
  nf_unregister_hook(&hook_src);
  nf_unregister_hook(&hook_dst);
  printk(KERN_INFO "GFD: unloaded\n");
}
