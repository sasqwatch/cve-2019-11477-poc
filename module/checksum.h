#ifndef __CHECKSUM_H__
#define __CHECKSUM_H__

#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/skbuff.h>
#include <net/tcp.h>
#include <net/udp.h>

void update_checksum(struct sk_buff *skb);

#endif /* __CHECKSUM_H__ */
