#ifdef _WIN32
#include "os_win32.c"
#else
#include "os_posix.c"
#endif

char exe_path_mpv[CIN_MAX_PATH_BYTES] = {0};
char exe_path_ytdlp[CIN_MAX_PATH_BYTES] = {0};
char exe_path_chatterino[CIN_MAX_PATH_BYTES] = {0};