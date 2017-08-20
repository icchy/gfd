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
  uint8_t state;
} TCP_ENTRY;

typedef enum {
  STATE_NONE = 0,
  STATE_TRACKED,
  STATE_UNTRACKED
} TCP_STATE;

TCP_ENTRY tcp_table[TABLE_SIZE];
size_t tcp_idx;


const uint32_t localhost_eth = IP_ADDR(192, 168, 18, 126);
const uint32_t localhost = IP_ADDR(127, 0, 0, 1);


// debug functions

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

void hexdump(const void* buf, size_t size) {
  int i, off = 0;
  char out[1024];
  printk(KERN_INFO "size: %d\n", size);
  if(size >= 1024) return;
  for(i = 0; i < size; i++) {
    off += snprintf(&out[off], 3, "%02x", *((uint8_t*)buf+i));
  }
  out[off] = '\0';
  printk(KERN_INFO "dump: %s\n", out);
}


// utils

inline void *memmem(const void* haystack, size_t haystacklen, 
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

int check_ip(uint32_t ip)
{
  // 192.168.18.*
  if(ip&0xff == 192
      && (ip>>8)&0xff == 168
      && (ip>>16)&0xff == 18) {
    return 1;
  }
  return 0;
}


typedef struct {
  uint16_t size;
  uint16_t id;

#if __BYTE_ORDER == __LITTLE_ENDIAN
  uint16_t qr:1;
  uint16_t opcode:4;
  uint16_t aa:1;
  uint16_t tc:1;
  uint16_t rd:1;
  uint16_t ra:1;
  uint16_t z:3;
  uint16_t rcode:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
  uint16_t rcode:4;
  uint16_t z:3;
  uint16_t ra:1;
  uint16_t rd:1;
  uint16_t tc:1;
  uint16_t aa:1;
  uint16_t opcode:4;
  uint16_t qr:1;
#else
# error "unknown endian"
#endif


  uint16_t qdcount;
  uint16_t ancount;
  uint16_t nscount;
  uint16_t arcount;
} TCP_DNS_HEADER;

int check_dns(const void* data, size_t datalen)
{
  /*
   * check dns request
   */

  TCP_DNS_HEADER *hdr;
  void *q; // query pointer
  uint8_t l; // label

  hdr = (TCP_DNS_HEADER*)data; // skip size

  if(hdr->qr) // request query?
    return -1;
  
  if(hdr->qdcount == 0)
    return -2;

  if(hdr->z) // reserved bits
    return -3;

  q = (void*)hdr+sizeof(TCP_DNS_HEADER);
  while(1) {
    if(q - data >= datalen)
      return -4;
    l = *(uint8_t*)q;
    if(l == 0)
      break;
    q += l+1;
  }
  q++;

  // check type
  if(ntohs(*(uint16_t*)q) != 1) {
    return -5;
  }

  // check class
  q += sizeof(uint16_t);
  if(ntohs(*(uint16_t*)q) != 1) {
    return -6;
  }

  return 0;
}


#define CRLF "\r\n"
#define SP " "

int check_http(const void* data, size_t datalen) 
{
  /*
   * check http header
   *
   * RFC7230
   *
   */

  int i;
  void *sep, *method, *req_target, *http_ver, *body;
  size_t remain, method_len, req_target_len, http_ver_len;

  // parse request line

  if((sep = memmem(data, datalen, CRLF, strlen(CRLF))) == NULL) {
    return -1;
  }
  remain = sep - data;

  // parse method
  method = data;
  if((sep = memmem(method, remain, SP, strlen(SP))) == NULL) {
    return -2;
  }
  method_len = sep - method;
  remain -= method_len+1;

  // reject if method includes strange char
  for(i = 0; i < method_len; ++i)
    if(*((char*)method+i) < 'A' || 'Z' < *((char*)method+i))
      return -3;

  // parse request target
  req_target = method + method_len + 1;
  if((sep = memmem(req_target, remain, SP, strlen(SP))) == NULL) {
    return -4;
  }
  req_target_len = sep - req_target;
  remain -= req_target_len+1;

  // not check validity but chars
  for(i = 0; i < req_target_len; ++i)
    if(*((char*)req_target+i) < 0x21 || 0x7e < *((char*)req_target+i))
      return -5;

  // parse http version
  http_ver = req_target + req_target_len + 1;
  http_ver_len = remain;

  if(http_ver_len != 8) {
    return -6;
  }

  // RFC7230
  // HTTP-version  = HTTP-name "/" DIGIT "." DIGIT
  // HTTP-name     = %x48.54.54.50 ; "HTTP", case-sensitive
  if(memcmp(http_ver, "HTTP/", 5)) {
    return -7;
  }
  if(*((char*)http_ver+5) < '0' || '9' < *((char*)http_ver+5)) {
    return -8;
  }
  if(*((char*)http_ver+6) != '.') {
    return -9;
  }
  if(*((char*)http_ver+7) < '0' || '9' < *((char*)http_ver+7)) {
    return -10;
  }

  return 0;
}


// hook utils

static int dns_table_push(struct iphdr *iph, struct udphdr *udph, DNS_ENTRY table[]) 
{
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

static uint32_t dns_table_pop(struct iphdr *iph, struct udphdr *udph, DNS_ENTRY table[]) 
{
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


static int tcp_table_push(struct iphdr *iph, struct tcphdr *tcph, TCP_ENTRY table[]) 
{
  int start = tcp_idx++;

  while(start != (tcp_idx&(TABLE_SIZE-1))) {
    tcp_idx &= (TABLE_SIZE-1);
    if(table[tcp_idx].state == STATE_NONE) {
      table[tcp_idx].saddr = iph->saddr;
      table[tcp_idx].daddr = iph->daddr;
      table[tcp_idx].sport = tcph->source;
      table[tcp_idx].dport = tcph->dest;
      table[tcp_idx].state = STATE_TRACKED;
      return 0;
    }
    tcp_idx++;
  }
  return -1;
}

static TCP_ENTRY *tcp_table_get(struct iphdr *iph, struct tcphdr *tcph, TCP_ENTRY table[]) 
{
  int i;
  uint8_t state;

  for(i = 0; i < TABLE_SIZE; ++i) {
    if((table[i]).state == STATE_NONE)
      continue;

    if(table[i].saddr == iph->daddr
        && table[i].daddr == iph->saddr
        && table[i].sport == tcph->dest
        && table[i].dport == tcph->source) {
      return &table[i];
    }
    if(table[i].saddr == iph->saddr
        && table[i].daddr == iph->daddr
        && table[i].sport == tcph->source
        && table[i].dport == tcph->dest) {
      return &table[i];
    }
  }
  return NULL;
}


static int calc_csum(struct sk_buff *skb) 
{
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

    // deny except udp port 53 (DNS)
    if(be16_to_cpu(udph->source) != 53)
      return NF_DROP;

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
    // deny except udp port 53 (DNS)
    if(be16_to_cpu(udph->dest) != 53)
      return NF_DROP;

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
// check if the protocol is HTTP on establishing TCP connection

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
  TCP_ENTRY *table;

  int err;


  // load ip header
  if((iph = ip_hdr(skb)) == NULL)
    return NF_ACCEPT;

  // only IPv4
  if(iph->version != 4)
    return NF_ACCEPT;

  if(iph->protocol == IPPROTO_TCP && (tcph = tcp_hdr(skb))) {
    // check ip range
    if(check_ip(iph->saddr) || check_ip(iph->daddr))
      return NF_ACCEPT;

    tcpdata = (uint8_t *)tcph + tcph->doff*4;
    tcpdatalen = ntohs(iph->tot_len) - (iph->ihl*4 + tcph->doff*4);

    // check if packet includes "ictsc"
    if(memmem(tcpdata, tcpdatalen, "ictsc", 5)) {
      // rewrite FIN flag
      tcph->fin = 1;
      calc_csum(skb);
    }

    if((table = tcp_table_get(iph, tcph, tcp_table)) == NULL) {
      if(tcph->syn && tcp_table_push(iph, tcph, tcp_table)) {
        printk(KERN_INFO "GFD: failed to push tcp entry\n");
      }
    }
    else if(table->state == STATE_TRACKED){
      // TRACKED: on establishing connection
      if(tcpdatalen > 0) {
        if(be16_to_cpu(tcph->dest) == 53 || be16_to_cpu(tcph->source) == 53) {
          if(err = check_dns(tcpdata, tcpdatalen)) {
            // packet is not DNS
            tcph->fin = 1;
            calc_csum(skb);
          }
          else {
            table->state = STATE_UNTRACKED;
          }
        }
        else {
          if(err = check_http(tcpdata, tcpdatalen)) {
            // packet is not HTTP
            tcph->fin = 1;
            calc_csum(skb);
          }
          else {
            table->state = STATE_UNTRACKED;
          }
        }
      }
    }

    if(tcph->fin || tcph->rst) {
      if(table = tcp_table_get(iph, tcph, tcp_table)) {
        // free entry
        table->state = STATE_NONE;
      }
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
    tcp_table[i].state = STATE_NONE;
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
