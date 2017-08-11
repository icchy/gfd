#include <linux/string.h>

#include "utils.h"


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

static int load_and_check_header(struct sk_buff *skb, struct iphdr *iph, struct tcphdr *tcph, struct udphdr *udph) {
  // load ip header
  if((iph = ip_hdr(skb)) == NULL)
    return -1;

  // allow only IPv4
  if(iph->version != 4)
    return -1;

  if(iph->protocol == IPPROTO_TCP && tcph != NULL && (tcph = tcp_hdr(skb)))
    return 0;

  if(iph->protocol == IPPROTO_UDP && udph != NULL && (udph = udp_hdr(skb)))
    return 0;

  return -1;
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

void hexdump(uint8_t *buf, size_t size) {
  int i;
  int off = 0;
  char out[512];
  if(size >= 512) return;
  for(i = 0; i < size; i++) {
    off += snprintf(&out[off], 3, "%02x", buf[i]);
  }
  out[off] = '\0';
  printk(KERN_INFO "dump(%d): %s\n", (int)size, out);
}
