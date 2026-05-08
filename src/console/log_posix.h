#ifndef CIN_LOG_POSIX_H
#define CIN_LOG_POSIX_H

#include <pthread.h>
#include <stdint.h>

extern pthread_t listener_thread;
extern int32_t interrupt_pipe[2];

void interrupt_start(void);
void interrupt_finish(void);

#endif