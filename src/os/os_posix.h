#ifndef CIN_OS_POSIX_H
#define CIN_OS_POSIX_H

#include "sys/types.h"

typedef struct COORD {
  short X;
  short Y;
} COORD;

typedef struct RECT {
  ssize_t right;
  ssize_t bottom;
  ssize_t left;
  ssize_t top;
} RECT;

typedef unsigned long HWND;

#endif