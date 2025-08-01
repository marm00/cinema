# cinema

A CLI tool to search and play local and online videos simultaneously, using mpv.

Compiled with `clang cinema.c cJSON.c libsais.c -std=c11 -O3 -march=znver2 -fopenmp -DLIBSAIS_OPENMP -DNDEBUG -luser32 -o cinema.exe`

<https://mpv.io/installation/>\
<https://github.com/shinchiro/mpv-winbuild-cmake/releases/download/20250227/mpv-x86_64-20250227-git-5338f4b.7z>

## mpv configuration

TODO: mpv_config_dir in config somewhere\
TODO: specify yt-dlp dependency

If the `mpv` executable is located inside this folder, configuration in `./portable_config/` is used.\
Otherwise, system files are used. If you want to target another directory, use `mpv_config_dir`\
See <https://mpv.io/manual/stable/#files-on-windows> and <https://github.com/mpv-player/mpv/tree/master/etc> for examples.
