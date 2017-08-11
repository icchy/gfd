/*
 * Great Firewall daemon
 * This LKM was built for The 8th ICT TroubleShooting Contest, ICTSC8.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "hook_dns.h"
#include "utils.h"

MODULE_AUTHOR("Ryo ICHIKAWA");
MODULE_DESCRIPTION("Great firewall daemon");
MODULE_VERSION("0.1");


// static unsigned handle_hook_in(const struct nf_hook_ops *ops,
//     struct sk_buff *skb,
//     const struct net_device *in,
//     const struct net_device *out,
//     int (*okfn)(struct sk_buff*))
// {
//   struct iphdr *iph;
//   struct tcphdr *tcph;
//   struct udphdr *udph;
//
//   uint8_t *tcpdata;
//   uint32_t tcpdatalen;
//   uint32_t saddr;
//
//   // load ip header
//   if((iph = ip_hdr(skb)) == NULL)
//     return NF_DROP;
//
//   // allow only IPv4
//   if(iph->version != 4)
//     return NF_DROP;
//
//   // allow to localhost
//   if(iph->daddr == localhost_eth || iph->daddr == localhost) {
//     return NF_ACCEPT;
//   }
//
//   if(iph->protocol == IPPROTO_TCP && (tcph = tcp_hdr(skb))) {
//     // check if packet is HTTP
//
//
//     // check if packet includes "ictsc"
//
//     tcpdata = (uint8_t *)tcph + tcph->doff*4;
//     tcpdatalen = ntohs(iph->tot_len) - (iph->ihl*4 + tcph->doff*4);
//
//     if(table_pop(skb)) {
//       // rewrite RST flag
//       tcph->rst = 1;
//       calc_csum(skb);
//       return NF_ACCEPT;
//     }
//
//     if(memmem(tcpdata, tcpdatalen, "ictsc", 5) != NULL) {
//       if(table_push(skb)) {
//         printk(KERN_INFO "GFD: failed to push tcp entry\n");
//       }
//       // rewrite RST flag
//       tcph->rst = 1;
//       calc_csum(skb);
//     }
//   }
//
//   if(iph->protocol == IPPROTO_UDP && (udph = udp_hdr(skb))) {
//     // rewrite dest if port 53
//
//     // allow except udp port 53 (DNS)
//     if(be16_to_cpu(udph->source) != 53)
//       return NF_DROP;
//
//     // overwrite src
//     if((saddr = table_pop(skb)) == 0x0) {
//       printk(KERN_INFO "GFD: failed to pop udp entry\n");
//       return NF_ACCEPT;
//     }
//     iph->saddr = saddr;
//     calc_csum(skb);
//   }
//
//   return NF_ACCEPT;
// }
//
// static unsigned handle_hook_out(const struct nf_hook_ops *ops,
//     struct sk_buff *skb,
//     const struct net_device *in,
//     const struct net_device *out,
//     int (*okfn)(struct sk_buff*))
// {
//   struct iphdr *iph;
//   struct tcphdr *tcph;
//   struct udphdr *udph;
//
//   uint8_t *tcpdata;
//   uint32_t tcpdatalen;
//
//   // load ip header
//   if((iph = ip_hdr(skb)) == NULL)
//     return NF_DROP;
//
//   // allow only IPv4
//   if(iph->version != 4)
//     return NF_DROP;
//
//   // allow from localhost
//   if(iph->saddr == localhost_eth || iph->saddr == localhost) {
//     return NF_ACCEPT;
//   }
//
//   if(iph->protocol == IPPROTO_TCP && (tcph = tcp_hdr(skb))) {
//     if(be16_to_cpu(tcph->dest) != 80
//         && be16_to_cpu(tcph->source) != 22)
//       return NF_DROP;
//
//     // check if packet includes "ictsc"
//
//     tcpdata = (uint8_t *)tcph + tcph->doff*4;
//     tcpdatalen = ntohs(iph->tot_len) - (iph->ihl*4 + tcph->doff*4);
//
//     if(table_pop(skb)) {
//       // rewrite RST flag
//       tcph->rst = 1;
//       return NF_ACCEPT;
//     }
//
//     if(memmem(tcpdata, tcpdatalen, "ictsc", 5) != NULL) {
//       if(table_push(skb)) {
//         printk(KERN_INFO "GFD: failed to push tcp entry\n");
//       }
//       // rewrite RST flag
//       tcph->rst = 1;
//       calc_csum(skb);
//     }
//   }
//
//   if(iph->protocol == IPPROTO_UDP && (udph = udp_hdr(skb))) {
//     // allow except udp port 53 (DNS)
//     if(be16_to_cpu(udph->dest) != 53)
//       return NF_ACCEPT;
//
//     // print_ipaddr("dst_hook src", iph->saddr);
//     // print_ipaddr("dst_hook dst", iph->daddr);
//
//     // overwrite dst
//     if(table_push(skb)) {
//       printk(KERN_INFO "GFD: failed to push udp entry\n");
//     }
//     csum_replace4(&iph->check, iph->daddr, localhost_eth);
//     csum_replace4(&udph->check, iph->daddr, localhost_eth);
//     iph->daddr = localhost_eth;
//   }
//
//   return NF_ACCEPT;
// }


// register/unregister hooks

int init_module()
{
  int err;

  // init table
  // for(idx = 0; idx < TABLE_SIZE; ++idx) {
  //   table[idx].sport = 0;
  //   table[idx].dport = 0;
  // }
  // idx = 0;

  if((err = nf_register_hook(&hook_dns_in)) < 0) {
    return err;
  }

  if((err = nf_register_hook(&hook_dns_out)) < 0) {
    return err;
  }

  printk(KERN_INFO "GFD: loaded\n");

  return 0;
}


void cleanup_module()
{
  nf_unregister_hook(&hook_dns_in);
  nf_unregister_hook(&hook_dns_out);
  printk(KERN_INFO "GFD: unloaded\n");
}
