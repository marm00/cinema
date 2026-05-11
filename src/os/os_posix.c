#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "os.h"

struct Cin_System cin_system = {
    .page_size = 4096,
    .alloc_type = MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE,
    .threads = 1};

void *os_alloc(size_t bytes) {
  void *chunk = mmap(NULL, bytes, PROT_READ | PROT_WRITE,
                     (int32_t)cin_system.alloc_type, -1, 0);
  if (chunk == MAP_FAILED) {
    printf("Cinema crashed trying to allocate memory with mmap: %s", strerror(errno));
    // https://kernel.googlesource.com/pub/scm/linux/kernel/git/nico/archive/+/v0.97/include/linux/errno.h
    exit(1);
  }
#ifdef MADV_HUGEPAGE
  madvise(chunk, bytes, MADV_HUGEPAGE);
#endif
  return chunk;
}

bool init_os(void) {
  cin_system.threads = (int32_t)sysconf(_SC_NPROCESSORS_ONLN);
#ifdef CIN_OPENMP
  omp_set_num_threads(cin_system.threads);
#endif
  return true;
}

void os_random(uint32_t *out) {
  uint32_t random;
  FILE *f = fopen("/dev/urandom", "rb");
  if (!f) {
    // log_last_error("Failed to open /dev/urandom");
    random = 0;
  } else if (fread(&random, sizeof(random), 1, f) != 1) {
    // log_last_error("Failed to read /dev/urandom");
    random = 0;
  }
  fclose(f);
  *out = random;
}

void os_sleep(long millis) {
  ssize_t nanos = millis * 1000 * 1000;
  struct timespec duration = {
      .tv_sec = nanos / (1000 * 1000 * 1000),
      .tv_nsec = nanos % (1000 * 1000 * 1000)};
  nanosleep(&duration, 0);
}