#ifndef __SYS_TIMER_H__
#define __SYS_TIMER_H__
#include <stdio.h>
#include <stdint.h>

static uint32_t get_cntfrq(void)
{
  uint32_t val;
  val = 0;

  asm volatile("mrs %0, cntfrq_el0" : "=r" (val));

  return val;
}


static uint64_t get_cntpct(void)
{
  uint64_t val;
  val = 0;
  
  asm volatile("isb");
  asm volatile("mrs %0, cntpct_el0" : "=r" (val));

  return (val);
}

static uint64_t get_cntvct(void)
{
  uint64_t val;
  val = 0;
  
  asm volatile("isb");
  asm volatile("mrs %0, cntvct_el0" : "=r" (val));

  return (val);
}

static uint64_t get_system_time(void)
{
  uint64_t time;
  uint64_t cntvct;
  uint32_t cntfrq;
  time = 0;
  cntvct = get_cntvct();
  cntfrq = get_cntfrq();

  time = (cntvct / cntfrq) * 1000 + ((cntvct % cntfrq) / (cntfrq / 1000));

  return time;
}
#endif /* __SYS_TIMER_H__ */
