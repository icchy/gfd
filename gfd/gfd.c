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
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");

#define IP_ADDR(o1,o2,o3,o4) (uint32_t)((o4<<24)|(o3<<16)|(o2<<8)|o1)
#define TABLE_SIZE (1<<4)

typedef struct {
  uint32_t saddr;
  uint32_t daddr;
  uint16_t sport;
} DNS_ENTRY;

DNS_ENTRY dns_table[TABLE_SIZE];
size_t dns_idx;

typedef struct {
  uint32_t saddr;
  uint32_t daddr;
  uint16_t sport;
  uint16_t dport;
  uint32_t last_seq;
  uint8_t state;
} TCP_ENTRY;

TCP_ENTRY tcp_table[TABLE_SIZE];
size_t tcp_idx;


const uint32_t localhost_eth = IP_ADDR(192, 168, 18, 126);
const uint32_t localhost = IP_ADDR(127, 0, 0, 1);


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


static int dns_table_push(struct iphdr *iph, struct udphdr *udph, DNS_ENTRY table[]) {
  int start = dns_idx++;

  while(start != (dns_idx&(TABLE_SIZE-1))) {
    dns_idx &= (TABLE_SIZE-1);
    if(!table[dns_idx].sport) {
      table[dns_idx].saddr = iph->saddr;
      table[dns_idx].daddr = iph->daddr;
      table[dns_idx].sport = udph->source;
      return 0;
    }
    dns_idx++;
  }
  return -1;
}

static uint32_t dns_table_pop(struct iphdr *iph, struct udphdr *udph, DNS_ENTRY table[]) {
  int i;

  for(i = 0; i < TABLE_SIZE; ++i) {
    if(table[i].sport == udph->dest
        && table[i].saddr == iph->daddr) {
      table[i].sport = 0;
      return table[i].daddr;
    }
  }
  return 0;
}


static int tcp_table_push(struct iphdr *iph, struct tcphdr *tcph, TCP_ENTRY table[]) {
  int start = tcp_idx++;

  while(start != (tcp_idx&(TABLE_SIZE-1))) {
    tcp_idx &= (TABLE_SIZE-1);
    if(!table[tcp_idx].sport && !table[tcp_idx].dport) {
      table[tcp_idx].saddr = iph->saddr;
      table[tcp_idx].daddr = iph->daddr;
      table[tcp_idx].sport = tcph->source;
      table[tcp_idx].dport = tcph->dest;
      return 0;
    }
    tcp_idx++;
  }
  return -1;
}

static uint32_t tcp_table_pop(struct iphdr *iph, struct tcphdr *tcph, TCP_ENTRY table[]) {
  int i;

  for(i = 0; i < TABLE_SIZE; ++i) {
    if(table[i].saddr == iph->daddr
        && table[i].daddr == iph->saddr
        && table[i].sport == tcph->dest
        && table[i].dport == tcph->source) {
      table[i].sport = 0;
      table[i].dport = 0;
      return table[i].daddr;
    }
  }
  return 0;
}

static int calc_csum(struct sk_buff *skb) {
  struct iphdr *iph;
  struct tcphdr *tcph;
  struct udphdr *udph;

  uint8_t *hdr;
  uint32_t hdrlen;
  uint16_t *check;

  if((iph = ip_hdr(skb)) == NULL)
    return -1;

  hdrlen = ntohs(iph->tot_len) - iph->ihl*4;

  if(iph->protocol == IPPROTO_TCP) {
    if((tcph = tcp_hdr(skb)) == NULL)
      return -1;
    hdr = (uint8_t*)tcph;
    check = &tcph->check;
  } else if(iph->protocol == IPPROTO_UDP) {
    if((udph = udp_hdr(skb)) == NULL)
      return -1;
    hdr = (uint8_t*)udph;
    check = &udph->check;
  } else {
    return -1;
  }

  iph->check = 0;
  iph->check = ip_fast_csum(iph, iph->ihl);

  *check = 0;
  *check = csum_tcpudp_magic(iph->saddr, iph->daddr,
                              hdrlen,
                              iph->protocol,
                              csum_partial(hdr, hdrlen, 0));
  skb->ip_summed = CHECKSUM_COMPLETE;

  return 0;
}


// DNS hook module

static unsigned handle_hook_dns_in(const struct nf_hook_ops *ops,
    struct sk_buff *skb,
    const struct net_device *in,
    const struct net_device *out,
    int (*okfn)(struct sk_buff*))
{
  struct iphdr *iph;
  struct udphdr *udph;
  uint32_t saddr;


  // load ip header
  if((iph = ip_hdr(skb)) == NULL)
    return NF_ACCEPT;

  // only IPv4
  if(iph->version != 4)
    return NF_ACCEPT;

  // allow to localhost
  if(iph->daddr == localhost_eth || iph->daddr == localhost) {
    return NF_ACCEPT;
  }

  if(iph->protocol == IPPROTO_UDP && (udph = udp_hdr(skb))) {
    // rewrite dest if port 53

    // allow except udp port 53 (DNS)
    if(be16_to_cpu(udph->source) != 53)
      return NF_ACCEPT;

    // overwrite src
    if((saddr = dns_table_pop(iph, udph, dns_table)) == 0x0) {
      printk(KERN_INFO "GFD: failed to pop udp entry\n");
      return NF_ACCEPT;
    }
    iph->saddr = saddr;
    calc_csum(skb);
  }
    
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


  // load ip header
  if((iph = ip_hdr(skb)) == NULL)
    return NF_ACCEPT;

  // only IPv4
  if(iph->version != 4)
    return NF_ACCEPT;

  // allow from localhost
  if(iph->saddr == localhost_eth || iph->saddr == localhost) {
    return NF_ACCEPT;
  }

  if(iph->protocol == IPPROTO_UDP && (udph = udp_hdr(skb))) {
    // allow except udp port 53 (DNS)
    if(be16_to_cpu(udph->dest) != 53)
      return NF_ACCEPT;

    // overwrite dst
    if(dns_table_push(iph, udph, dns_table)) {
      printk(KERN_INFO "GFD: failed to push udp entry\n");
    }
    csum_replace4(&iph->check, iph->daddr, localhost_eth);
    csum_replace4(&udph->check, iph->daddr, localhost_eth);
    iph->daddr = localhost_eth;
  }

  return NF_ACCEPT;
}


// TCP hook module

static unsigned handle_hook_tcp(const struct nf_hook_ops *ops,
    struct sk_buff *skb,
    const struct net_device *in,
    const struct net_device *out,
    int (*okfn)(struct sk_buff*))
{
  struct iphdr *iph;
  struct tcphdr *tcph;

  uint8_t *tcpdata;
  uint32_t tcpdatalen;


  // load ip header
  if((iph = ip_hdr(skb)) == NULL)
    return NF_ACCEPT;

  // only IPv4
  if(iph->version != 4)
    return NF_ACCEPT;

  if(iph->protocol == IPPROTO_TCP && (tcph = tcp_hdr(skb))) {
    if(be16_to_cpu(tcph->dest) != 10080 && be16_to_cpu(tcph->source) != 10080)
      return NF_ACCEPT;

    // check if packet includes "ictsc"

    tcpdata = (uint8_t *)tcph + tcph->doff*4;
    tcpdatalen = ntohs(iph->tot_len) - (iph->ihl*4 + tcph->doff*4);

    print_ipaddr("src", iph->saddr);
    print_ipaddr("dst", iph->daddr);

    if(tcp_table_pop(iph, tcph, tcp_table)) {
      // rewrite RST flag
      tcph->rst = 1;
      return NF_ACCEPT;
    }

    if(memmem(tcpdata, tcpdatalen, "ictsc", 5) != NULL) {
      if(tcp_table_push(iph, tcph, tcp_table)) {
        printk(KERN_INFO "GFD: failed to push tcp entry\n");
      }
      // rewrite RST flag
      tcph->rst = 1;
    }
  }

  return NF_ACCEPT;
}


// netfilter hooks

static struct nf_hook_ops hook_dns_in = {
  .hook = handle_hook_dns_in,
  .pf = PF_INET,
  .hooknum = NF_INET_LOCAL_OUT,
  .priority = NF_IP_PRI_FILTER,
};

static struct nf_hook_ops hook_dns_out = {
  .hook = handle_hook_dns_out,
  .pf = PF_INET,
  .hooknum = NF_INET_PRE_ROUTING,
  .priority = NF_IP_PRI_FILTER,
};

static struct nf_hook_ops hook_tcp = {
  .hook = handle_hook_tcp,
  .pf = PF_INET,
  .hooknum = NF_INET_FORWARD,
  .priority = NF_IP_PRI_FILTER,
};


// register handler

int init_module()
{
  int err;
  int i;

  // init table
  for(i = 0; i < TABLE_SIZE; ++i) {
    dns_table[i].sport = 0;
    tcp_table[i].sport = 0;
    tcp_table[i].dport = 0;
  }
  dns_idx = 0;
  tcp_idx = 0;

  if((err = nf_register_hook(&hook_dns_in)) < 0) {
    return err;
  }

  if((err = nf_register_hook(&hook_dns_out)) < 0) {
    return err;
  }

  if((err = nf_register_hook(&hook_tcp)) < 0) {
    return err;
  }

  printk(KERN_INFO "GFD: loaded\n");

  return 0;
}

void cleanup_module()
{
  nf_unregister_hook(&hook_dns_in);
  nf_unregister_hook(&hook_dns_out);
  nf_unregister_hook(&hook_tcp);
  printk(KERN_INFO "GFD: unloaded\n");
}
