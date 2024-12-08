#include <cstdint>

#ifndef KERNELS_H
#define KERNELS_H

#define AES_BLOCK_SIZE      16
#define AES_ROUNDS_256      14


__global__ void GCTRKernel(const uint8_t *ICB, const uint8_t *val, int numAESBlocks, uint8_t *result,
                           const uint8_t *key, const uint8_t *roundkeys);

__device__ void Paes_encrypt_256(const uint8_t *roundkeys, const uint8_t *plaintext, uint8_t *ciphertext);

__device__ void inv_shift_rows(uint8_t *state);

__device__ void shift_rows(uint8_t *state);

__device__ inline uint8_t mul2(uint8_t a);

__global__ void GHASHKernel(uint8_t *H, uint8_t *val,int Valsize, int increment ,uint8_t *result);

__device__  void gf128Power(uint8_t *H, int power, uint8_t *result);

__device__ void gf128Multiply(uint8_t *X, uint8_t *Y, uint8_t *result);

#endif
