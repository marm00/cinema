#ifndef CIN_OS_H
#define CIN_OS_H

#include <stdbool.h>
#include <stdint.h>

extern struct Cin_System {
  size_t page_size;
  uint32_t alloc_type;
  int32_t threads;
} cin_system;

void *os_alloc(size_t bytes);
bool init_os(void);
void os_random(uint32_t *out);

#endif