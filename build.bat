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

set config=debug
if "%release%"=="1" set config=release
if "%asan%"=="1" set config=%config%-asan
if "%parallel%"=="0" set config=%config%-nomp
set build=build\%config%
if not exist %build% mkdir %build%

set warn= -Wall -Wextra -Wpedantic -Wstrict-prototypes -Wmissing-prototypes -Wconversion -Wsign-conversion -Wshadow -Wformat=2 -Wno-unused-function
if "%asan%"=="1" set sanitize= -fsanitize=address && echo [address sanitizer]
if "%asan%"=="0" set sanitize=

if not exist %build%\libsais.o (
    echo [building libsais]
    clang -O3 -fopenmp -DLIBSAIS_OPENMP -DNDEBUG %sanitize% -c src\third_party\libsais.c -o %build%\libsais.o
)

if "%release%"=="1" (
    echo [release build]
    set debug_info=
    clang -std=c11 -O2 -DNDEBUG %omp% %sanitize% %log_level% -I.\src\ -flto=thin -c cinema.c -o %build%\cinema.o
) else (
    if "!log_level!"=="" set log_level=-DLOG_LEVEL=3 && echo [logs: debug]
    echo [debug build]
    set debug_info= -Wl,/DEBUG -Wl,/PDB:%build%\cinema.pdb
    clang -std=c11 -g -gcodeview %omp% %warn% %sanitize% !log_level! -I.\src\ -c cinema.c -o %build%\cinema.o
)

llvm-rc cinema.rc -fo %build%\cinema.res
clang -fuse-ld=lld-link %omp% %sanitize% %debug_info% -o %build%\cinema.exe %build%\cinema.o %build%\libsais.o %build%\cinema.res

copy /y %build%\cinema.exe build\cinema.exe >nul
if "%debug%"=="1" copy /y %build%\cinema.pdb build\cinema.pdb >nul