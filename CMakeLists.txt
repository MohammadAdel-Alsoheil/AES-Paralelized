cmake_minimum_required(VERSION 3.25)
project(AES_Paralelized)

set(CMAKE_CXX_STANDARD 14)

add_executable(AES_Paralelized
        AES.cpp aes_stages/SubBytes.cpp aes_stages/ShiftRows.cpp aes_stages/MixColumns.cpp aes_stages/KeyExpansion.cpp GCM.cpp Utils.cpp Utils.h Ghash.cpp Ghash.h
        GCM_MPI.cpp
        GCM_OpenMP.cpp
        CudaC/kernelsGCM.cu
        CudaC/aes.h
        CudaC/aes.c
        OCB.cpp
)