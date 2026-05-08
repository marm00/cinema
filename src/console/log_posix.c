#include <pthread.h>
#include <unistd.h>

#include "log.h"
#include "log_posix.h"

static pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER;

void lock_logs(void) {
  pthread_mutex_lock(&log_lock);
}

void unlock_logs(void) {
  pthread_mutex_unlock(&log_lock);
}

pthread_t listener_thread = 0;
int32_t interrupt_pipe[2];
static pthread_mutex_t interrupt_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t interrupt_done = PTHREAD_COND_INITIALIZER;
static bool interrupt_pending = false;

void interrupt_start(void) {
  pthread_mutex_lock(&interrupt_lock);
  interrupt_pending = true;
  write(interrupt_pipe[1], "x", 1);
  while (interrupt_pending) {
    pthread_cond_wait(&interrupt_done, &interrupt_lock);
  }
  pthread_mutex_unlock(&interrupt_lock);
}

void interrupt_finish(void) {
  char _val;
  read(interrupt_pipe[0], &_val, 1);
  pthread_mutex_lock(&interrupt_lock);
  interrupt_pending = false;
  pthread_cond_signal(&interrupt_done);
  pthread_mutex_unlock(&interrupt_lock);
}
