cmake_minimum_required(VERSION 3.25)
project(AES_Paralelized)

set(CMAKE_CXX_STANDARD 14)

add_executable(AES_Paralelized
        AES.cpp SubBytes.cpp ShiftRows.cpp MixColumns.cpp KeyExpansion.cpp GCM.cpp)
