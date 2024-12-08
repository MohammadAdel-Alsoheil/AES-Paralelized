#include <cstdint>

#ifndef KERNELS_H
#define KERNELS_H

#define AES_BLOCK_SIZE      16
#define AES_ROUNDS_256      14






__global__ void GCTRKernel(const uint8_t* ICB, const uint8_t* val, int numAESBlocks, uint8_t* result, const uint8_t* key, const uint8_t* roundkeys);
__device__ void Paes_encrypt_256(const uint8_t *roundkeys, const uint8_t *plaintext, uint8_t *ciphertext);
#endif
