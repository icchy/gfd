#ifndef _INCLUDE_HOOK_DNS_H
#define _INCLUDE_HOOK_DNS_H

#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/skbuff.h>


static unsigned handle_hook_dns_in(const struct nf_hook_ops *,
    struct sk_buff *,
    const struct net_device *,
    const struct net_device *,
    int (*)(struct sk_buff*));

static unsigned handle_hook_dns_out(const struct nf_hook_ops *,
    struct sk_buff *,
    const struct net_device *,
    const struct net_device *,
    int (*)(struct sk_buff*));


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

#endif
