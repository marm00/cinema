@echo off
llvm-rc cinema.rc -fo cinema.res
clang cinema.c libsais.c cinema.res -std=c11 -O3 -DNDEBUG -fopenmp -DCIN_OPENMP -DLIBSAIS_OPENMP -flto=thin -fuse-ld=lld-link -o cinema.exe
