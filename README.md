# AES-256 on Galois Counter Mode (GCM) parallelized using OpenMP, MPI, and Cuda C
This Repo contains differnt versions of AES implmentation on Galois Counter Mode (GCM). Once you clone the code there different folders to consider mainly aes-stages, CudaC, and Project Code.

## aes-stages 
cd aes-stages
This directory contains steps of AES e.g MixColumns, SubBytes, ....

## Project-code
The main files are GCM.cpp, GCM-openMP, and GCM-MPI
in order to compile you can use:
1) g++ GCM.cpp AES.cpp Utils.cpp Ghash.cpp -o out
2) ./out
 The same follows for the MPI and OpenMP versions

## CudaC
This repo contains Cuda C code , in order to run the code 
1) cd CudaC
2) g++ -g Ghash.cpp ghash.o
3) g++ -g Utils.cpp utils.o
4) gcc -g aes.c aes.o
5) nvcc -o out GCM.cu kernels.cu ghash.o  aes.o utils.o
6) ./out

