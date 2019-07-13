#include "checksum.h"

void update_checksum(struct sk_buff *skb)
{
  struct iphdr *iph;

  iph = ip_hdr(skb);
  skb->ip_summed = CHECKSUM_NONE;
  skb->csum_valid = 0;

  iph->check = 0;
  iph->check = ip_fast_csum((u8 *)iph, iph->ihl);

  if ((iph->protocol == IPPROTO_TCP) || (iph->protocol == IPPROTO_UDP))
  {
    if (skb_is_nonlinear(skb))
      skb_linearize(skb);

    if (iph->protocol == IPPROTO_TCP)
    {
      struct tcphdr *tcph;
      unsigned int tcplen;

      tcph = tcp_hdr(skb);
      skb->csum = 0;
      tcplen = ntohs(iph->tot_len) - (iph->ihl * 4);
      tcph->check = 0;
      tcph->check = tcp_v4_check(tcplen, iph->saddr, iph->daddr, 
          csum_partial((char *)tcph, tcplen, 0));
    }
    else if (iph->protocol == IPPROTO_UDP)
    {
      struct udphdr *udph;
      unsigned int udplen;

      udph = udp_hdr(skb);
      skb->csum = 0;
      udplen = ntohs(iph->tot_len) - (iph->ihl * 4);
      udph->check = 0;
      udph->check = udp_v4_check(udplen, iph->saddr, iph->daddr, 
          csum_partial((char *)udph, udplen, 0));
    }
  }
}
