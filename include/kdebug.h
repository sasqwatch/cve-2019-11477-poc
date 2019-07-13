#ifndef __EDGE_LOG_H__
#define __EDGE_LOG_H__

#include <linux/time.h>
#include <linux/types.h>

#define SUCCESS 1
#define FAILURE 0

#ifdef DEBUG
#define kdebug(format, ...) \
  printk(KERN_DEBUG "[sack] %s:%s:%d: " format "\n", __FILE__, __func__, __LINE__, ## __VA_ARGS__);

#define kdebug_ip(msg, ip) \
  printk(KERN_DEBUG "[sack] %s:%s:%d: %s: %d.%d.%d.%d\n", __FILE__, __func__, __LINE__, msg, (ip & 0xff), ((ip >> 8) & 0xff), ((ip >> 16) & 0xff), ((ip >> 24) & 0xff));

#define kdebug_info(msg, ip, port) \
  printk(KERN_DEBUG "[sack] %s:%s:%d: %s: %d.%d.%d.%d:%d\n", __FILE__, __func__, __LINE__, msg, (ip & 0xff), ((ip >> 8) & 0xff), ((ip >> 16) & 0xff), ((ip >> 24) & 0xff), ntohs(port));
#else
#define kdebug(format, ...)
#define kdebug_ip(msg, ip)
#define kdebug_info(msg, ip, port)
#endif /* DEBUG */

#ifdef FINFO
#define kfstart(format, ...) printk(KERN_INFO "[sack] Start: %s: " format "\n", __func__, ## __VA_ARGS__)
#define kffinish(format, ...) printk(KERN_INFO "[sack] Finish: %s: " format "\n", __func__, ## __VA_ARGS__)
#else
#define kfstart(format, ...)
#define kffinish(format, ...)
#endif /* FINFO */

#endif /* __EDGE_LOG_H__ */
