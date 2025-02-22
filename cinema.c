#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

typedef struct {
  char filepath[512];
  int volume;
} FFplayArgs;

int main() {
  printf("Hello, World!\n");
  FFplayArgs args = {"D:\\Test\\1_49mb.mp4", 100};
  char command[512]; // figure out max buffer size
  snprintf(command, sizeof(command),
           "ffplay"
           " -loop 0"
           " -alwaysontop"
           " -volume %d"
           " %s", // File path
           args.volume,
           args.filepath);
  STARTUPINFO si = {0};
  si.cb = sizeof(si);
  PROCESS_INFORMATION pi = {0};
  // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa
  if (!CreateProcess(NULL,    // No module name (use command line)
                     command, // Command line
                     NULL,    // Process handle not inheritable
                     NULL,    // Thread handle not inheritable
                     FALSE,   // Set handle inheritance to FALSE
                     0,       // No creation flags
                     NULL,    // Use parent's environment block
                     NULL,    // Use parent's starting directory
                     &si,     // Pointer to STARTUPINFO structure
                     &pi)     // Pointer to PROCESS_INFORMATION structure
  ) {
    printf("Failed to start ffplay.\n");
  };
  printf("Playing: %s (PID: %lu)\n", args.filepath, pi.dwProcessId);
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);
  return 0;
}