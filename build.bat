@echo off
setlocal enabledelayedexpansion

for %%a in (%*) do set "%%~a=1"

if not "%release%"=="1" set debug=1
if "%debug%"=="1" set release=0
if "%release%"=="1" set debug=0

if not "%nomp%"=="1" set parallel=1
if "%nomp%"=="1" set parallel=0
if "%parallel%"=="1" echo [openmp on] && set omp= -fopenmp -DCIN_OPENMP -DLIBSAIS_OPENMP
if "%parallel%"=="0" echo [openmp off] && set omp=

set log_level=
if "%log_error%"=="1" set log_level=%log_level% -DLOG_LEVEL=0 && echo [logs: error]
if "%log_warning%"=="1" set log_level=%log_level% -DLOG_LEVEL=1 && echo [logs: warning]
if "%log_info%"=="1" set log_level=%log_level% -DLOG_LEVEL=2 && echo [logs: info]
if "%log_debug%"=="1" set log_level=%log_level% -DLOG_LEVEL=3 && echo [logs: debug]
if "%log_trace%"=="1" set log_level=%log_level% -DLOG_LEVEL=4 && echo [logs: trace]

set warn= -Wall -Wextra -Wpedantic -Wstrict-prototypes -Wmissing-prototypes -Wconversion -Wsign-conversion -Wshadow -Wformat=2 -Wno-unused-function
if "%asan%"=="1" set warn=%warn% -fsanitize=address && echo [address sanitizer]

llvm-rc cinema.rc -fo cinema.res

if "%release%"=="1" (
    echo [release build]
    clang cinema.c libsais.c cinema.res -std=c11 -O2 -DNDEBUG %omp% %log_level% -flto=thin -fuse-ld=lld-link -o cinema.exe
) else (
    if "!log_level!"=="" set log_level=-DLOG_LEVEL=3 && echo [logs: debug]
    echo [debug build]
    clang cinema.c libsais.c cinema.res -std=c11 -g -gcodeview %omp% %warn% !log_level! -fuse-ld=lld-link -Wl,/DEBUG -Wl,/PDB:cinema.pdb -o cinema.exe
)
