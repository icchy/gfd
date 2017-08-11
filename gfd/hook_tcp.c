// hook table definitions

static int table_push(struct sk_buff *skb) {
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

static uint32_t table_pop(struct sk_buff *skb) {
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
