@echo off

for %%a in (%*) do set "%%~a=1"

if not "%release%"=="1" set debug=1
if "%debug%"=="1" set release=0
if "%release%"=="1" set debug=0

if not "%nomp%"=="1" set parallel=1
if "%nomp%"=="1" set parallel=0
if "%parallel%"=="1" echo [openmp on] && set omp= -fopenmp -DCIN_OPENMP -DLIBSAIS_OPENMP
if "%parallel%"=="0" echo [openmp off] && set omp=

set warn= -Wall -Wextra -Wpedantic -Wstrict-prototypes -Wmissing-prototypes -Wconversion -Wsign-conversion -Wshadow -Wformat=2 -Wno-unused-function

llvm-rc cinema.rc -fo cinema.res

if "%release%"=="1" (
    echo [release build]
    clang cinema.c libsais.c cinema.res -std=c11 -O2 -DNDEBUG %omp% -flto=thin -fuse-ld=lld-link -o cinema.exe
) else (
    echo [debug build]
    clang cinema.c libsais.c cinema.res -std=c11 -g -gcodeview %omp% %warn% -fuse-ld=lld-link -Wl,/DEBUG -Wl,/PDB:cinema.pdb -o cinema.exe
)
