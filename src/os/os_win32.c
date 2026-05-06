#define _CRT_RAND_S
#define _CRT_SECURE_NO_DEPRECATE

#include "os.h"
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

struct Cin_System cin_system = {
    .page_size = 4096,
    .alloc_type = MEM_RESERVE | MEM_COMMIT,
    .threads = 1};

void *os_alloc(size_t bytes) {
  void *chunk = VirtualAlloc(NULL, bytes, cin_system.alloc_type, PAGE_READWRITE);
  if (!chunk) {
    uint32_t code = GetLastError();
    printf("Cinema crashed with code %u trying to allocate memory with VirtualAlloc", code);
    // https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes
    exit(1);
  }
  return chunk;
}

bool init_os(void) {
  SYSTEM_INFO system;
  GetSystemInfo(&system);
  cin_system.page_size = (size_t)system.dwPageSize;
  cin_system.threads = (int32_t)system.dwNumberOfProcessors;
  HANDLE token;
  if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &token)) {
    LUID luid;
    if (LookupPrivilegeValueW(NULL, L"SeLockMemoryPrivilege", &luid)) {
      TOKEN_PRIVILEGES p = {.PrivilegeCount = 1,
                            .Privileges[0] = {.Luid = luid, .Attributes = SE_PRIVILEGE_ENABLED}};
      AdjustTokenPrivileges(token, FALSE, &p, sizeof(p), NULL, NULL);
      if (GetLastError() == ERROR_SUCCESS) {
        cin_system.alloc_type |= MEM_LARGE_PAGES;
        cin_system.page_size = GetLargePageMinimum();
      }
    }
    CloseHandle(token);
  }
#ifdef CIN_OPENMP
  omp_set_num_threads(cin_system.threads);
#endif
  return true;
}

void os_random(uint32_t *out) {
  uint32_t random;
  rand_s(&random);
  *out = random;
}

void os_sleep(long millis) {
  Sleep((DWORD)millis);
}