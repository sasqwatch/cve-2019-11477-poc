#ifndef __TCPOPT_H__
#define __TCPOPT_H__

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <netinet/ip.h>
#include <linux/tcp.h>
#include "../include/debug.h"
#include "../include/defines.h"

#define TCPOPT_NO_OPERATION   0x1
#define TCPOPT_MSS            0x2
#define TCPOPT_WINDOW_SCALE   0x3
#define TCPOPT_SACK_PERMITTED 0x4
#define TCPOPT_SACK           0x5
#define TCPOPT_TIMESTAMP      0x8

#define TCPOPT_MAX_SIZE       40

#define PRINT_OPT_NO_OPERATION    0x1
#define PRINT_OPT_MSS             0x2
#define PRINT_OPT_WINDOW_SCALE    0x4
#define PRINT_OPT_SACK_PERMITTED  0x8
#define PRINT_OPT_SACK            0x10
#define PRINT_OPT_TIMESTAMP       0x20
#define PRINT_OPT_ALL             PRINT_OPT_NO_OPERATION | PRINT_OPT_MSS \
  | PRINT_OPT_WINDOW_SCALE | PRINT_OPT_SACK_PERMITTED | PRINT_OPT_SACK \
  | PRINT_OPT_TIMESTAMP

#define PTR_TO_VAL_4BYTES(p, v) \
  v = (((p[0] & 0xff) << 24) | ((p[1] & 0xff) << 16) \
      | ((p[2] & 0xff) << 8) | (p[3] & 0xff)); p += 4;
#define VAL_TO_PTR_2BYTES(v, p) \
  p[0] = (v >> 8) & 0xff; p[1] = v & 0xff; p += 2;
#define VAL_TO_PTR_4BYTES(v, p) \
  p[0] = (v >> 24) & 0xff; p[1] = (v >> 16) & 0xff; \
  p[2] = (v >> 8) & 0xff; p[3] = v & 0xff; p += 4;

struct tcpopt_st
{
  uint8_t type;
  void *val;
  struct tcpopt_st *next;
};

struct timestamp_st
{
  uint32_t ts;
  uint32_t echo_reply;
};

struct block_st
{
  uint32_t left;
  uint32_t right;
  struct block_st *next;
};

struct sack_st
{
  int num;
  struct block_st *head;
};

struct tcpopt_st *get_tcpopt_blocks(struct tcphdr *tcph);
void free_tcpopt_blocks(struct tcpopt_st *blks);

struct tcpopt_st *init_tcpopt_block(void);
void free_tcpopt_block(struct tcpopt_st *blk);

int modify_tcpopt_block(struct tcpopt_st *head, int type, void *val); 
void print_tcpopt_blocks(struct tcpopt_st *head, int flags);

int serialize_tcphdr(struct iphdr *iph, struct tcphdr *tcph, struct tcpopt_st *blks);

#endif /* __TCPOPT_H__ */
