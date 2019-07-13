#include <linux/module.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/netlink.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/skbuff.h>
#include <linux/delay.h>
#include <linux/inetdevice.h>
#include <net/sock.h>

#include "../include/defines.h"
#include "../include/kdebug.h"

#define INVALID 0

#define TRUE 1
#define FALSE 0

static struct nf_hook_ops send, recv;
struct sock *nl_sk = NULL;
struct iphdr *iph;
struct tcphdr *tcph;
struct udphdr *udph;
struct sk_buff *pkt;
char *data;
int data_len, ret;

unsigned int sending_hook(void *priv,
    struct sk_buff *skb,
    const struct nf_hook_state *state)
{
  __u16 dport;
  pkt = skb;
  if (!skb)
  {
    return NF_ACCEPT;
  }

  iph = (struct iphdr *)skb_network_header(pkt);
  if (!iph)
  {
    return NF_ACCEPT;
  }

  if (iph->protocol == IPPROTO_TCP)
  {
    tcph = (struct tcphdr *)skb_transport_header(pkt);
    dport = ntohs(tcph->dest);

    if (dport == TARGET_PORT)
    {
      __u32 saddr, daddr;
      __u16 sport;

      saddr = ntohl(iph->saddr);
      daddr = ntohl(iph->daddr);
      sport = ntohs(tcph->source);

      kdebug("Send from %d.%d.%d.%d:%u to %d.%d.%d.%d:%u",
        (saddr >> 24) & 0xff, (saddr >> 16) & 0xff,
        (saddr >> 8) & 0xff, saddr & 0xff, sport,
        (daddr >> 24) & 0xff, (daddr >> 16) & 0xff,
        (daddr >> 8) & 0xff, daddr & 0xff, dport);

      return NF_QUEUE;
    }
  }

  return NF_ACCEPT;
}

unsigned int receiving_hook(void *priv,
    struct sk_buff *skb,
    const struct nf_hook_state *state)
{
  __u16 sport;
  pkt = skb;

  if (!skb)
  {
    return NF_ACCEPT;
  }

  iph = (struct iphdr *)skb_network_header(pkt);

  if (!iph)
  {
    return NF_ACCEPT;
  }

  if (iph->protocol == IPPROTO_TCP)
  {
    tcph = (struct tcphdr *)skb_transport_header(pkt);
    sport = ntohs(tcph->source);

    if (sport == TARGET_PORT)
    {
      __u32 saddr, daddr;
      __u16 dport;

      saddr = ntohl(iph->saddr);
      daddr = ntohl(iph->daddr);
      dport = ntohs(tcph->dest);

      kdebug("Send from %d.%d.%d.%d:%u to %d.%d.%d.%d:%u",
        (saddr >> 24) & 0xff, (saddr >> 16) & 0xff,
        (saddr >> 8) & 0xff, saddr & 0xff, sport,
        (daddr >> 24) & 0xff, (daddr >> 16) & 0xff,
        (daddr >> 8) & 0xff, daddr & 0xff, dport);

      return NF_QUEUE;
    }
  }

  return NF_ACCEPT;
}

static int __init initialize(void)
{
  // Set a configuration of a netfilter
  send.hook     = sending_hook;
  send.hooknum  = NF_INET_POST_ROUTING;
  send.pf       = PF_INET;
  send.priority = NF_IP_PRI_LAST;

  recv.hook     = receiving_hook;
  recv.hooknum  = NF_INET_PRE_ROUTING;
  recv.pf       = PF_INET;
  recv.priority = NF_IP_PRI_LAST;

  kdebug("Entering");

  nf_register_net_hook(&init_net, &send);
  nf_register_net_hook(&init_net, &recv);
  kdebug("Register Netfilter Hook");

  //nf_register_hook(&nfho); for the lower version of the kernel.

  return 0;
}

static void __exit cleanup(void)
{
  nf_unregister_net_hook(&init_net, &send);
  nf_unregister_net_hook(&init_net, &recv);
  kdebug("Unregister Netfilter Hook");
  netlink_kernel_release(nl_sk);
  kdebug("Release Netlink Kernel Socket");
  //nf_unregister_hook(&nfho); for the lower version of the kernel.

}

module_init(initialize);
module_exit(cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("mmlab2014@mmlab.snu.ac.kr");
MODULE_DESCRIPTION("SACK Panic Interceptor");
