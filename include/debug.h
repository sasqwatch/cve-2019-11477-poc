#ifndef __DEBUG_H__
#define __DEBUG_H__

#include <stdio.h>
#include <stdlib.h>

#define SUCCESS 1
#define FAILURE 0

#ifdef DEBUG
#define debug(format, ...) printf("[sack] %s:%s:%d: " format "\n", __FILE__, __func__, __LINE__, ## __VA_ARGS__)
#else
#define debug(format, ...)
#endif /* DEBUG */

#ifdef FINFO
#define fstart(format, ...) printf("Start: %s: " format "\n", __func__, ## __VA_ARGS__)
#define ffinish(format, ...) printf("Finish: %s: " format "\n", __func__, ## __VA_ARGS__);
#else
#define fstart(format, ...)
#define ffinish(format, ...)
#endif /* FINFO */

/**
 * @brief Translate an integer to a corresponding IP address
 * @param ul a 32-bit integer
 * @return a string of an IP address
 */
static char *ul_to_ipv4(const uint32_t ul)
{
  fstart();
  char *ret;
  int ip[4];
  ip[0] = (ul >> 24) & 0xff;
  ip[1] = (ul >> 16) & 0xff;
  ip[2] = (ul >> 8) & 0xff;
  ip[3] = ul & 0xff;

  ret = (char *)malloc(sizeof(char) * 16);
  memset(ret, 0, 16);
  snprintf(ret, 16, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);

  ffinish();
  return ret;
}

/**
 * @brief Translate an IP address to a corresponding integer
 * @param ip a string of an IP address
 * @return a translated integer
 */
static uint32_t ipv4_to_ul(const char *ip)
{
  uint32_t ret;
  int i;
  const char *idx;

  fstart();

  idx = ip;
  ret = 0;

  for (i=0; i<4; i++)
  {
    char c;
    int n = 0;

    while (1)
    {
      c = *idx;
      idx++;

      if (c >= '0' && c <= '9')
      {
        n *= 10;
        n += c - '0';
      }
      else if ((i < 3 && c == '.') || i == 3)
      {
        break;
      }
      else
      {
        return FAILURE;
      }
    }

    if (n >= 256)
      return FAILURE;

    ret <<= 8;
    ret |= n;
  }

  ffinish();
  return ret;
}

#endif /* __DEBUG_H__ */
