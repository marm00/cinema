#!/bin/sh
set -e

for arg in "$@"; do
    eval "${arg}=1"
done

if [ "$release" != "1" ]; then debug=1; fi
if [ "$debug" = "1" ]; then release=0; fi
if [ "$release" = "1" ]; then debug=0; fi

if [ "$nomp" != "1" ]; then parallel=1; fi
if [ "$nomp" = "1" ]; then parallel=0; fi
if [ "$parallel" = "1" ]; then
    echo "[openmp on]"
    omp="-fopenmp -DCIN_OPENMP -DLIBSAIS_OPENMP"
else
    echo "[openmp off]"
    omp=""
fi

log_level=""
[ "$log_error" = "1" ]   && log_level="$log_level -DLOG_LEVEL=0" && echo "[logs: error]"
[ "$log_warning" = "1" ] && log_level="$log_level -DLOG_LEVEL=1" && echo "[logs: warning]"
[ "$log_info" = "1" ]    && log_level="$log_level -DLOG_LEVEL=2" && echo "[logs: info]"
[ "$log_debug" = "1" ]   && log_level="$log_level -DLOG_LEVEL=3" && echo "[logs: debug]"
[ "$log_trace" = "1" ]   && log_level="$log_level -DLOG_LEVEL=4" && echo "[logs: trace]"

warn="-Wall -Wextra -Wpedantic -Wstrict-prototypes -Wmissing-prototypes -Wconversion -Wsign-conversion -Wshadow -Wformat=2 -Wno-unused-function"
[ "$asan" = "1" ] && warn="$warn -fsanitize=address" && echo "[address sanitizer]"

compiler="${CC:-clang}"

if [ "$release" = "1" ]; then
    echo "[release build]"
    $compiler cinema.c -std=c11 -O2 -DNDEBUG $omp $log_level -I./src/ -D_GNU_SOURCE -flto=thin -o cinema
else
    [ -z "$log_level" ] && log_level="-DLOG_LEVEL=3" && echo "[logs: debug]"
    echo "[debug build]"
    $compiler cinema.c -std=c11 -g $omp $warn $log_level -I./src/ -D_GNU_SOURCE -o cinema
fi