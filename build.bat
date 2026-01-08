@echo off
clang cinema.c libsais.c -std=c11 -O3 -DNDEBUG -fopenmp -DCIN_OPENMP -DLIBSAIS_OPENMP -flto=thin -fuse-ld=lld-link -o cinema.exe
