//
// Created by 96176 on 12/5/2024.
//
#include <cuda_runtime.h>
#include <device_launch_parameters.h>
#include <iostream>
#include "kernelsGCM.h"




__device__ uint8_t YO[16]; // used for GHASH
// AES ENCYPTION AS A __device__
__constant__ uint8_t RC[] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

/*
 * Sbox
 */
__constant__ uint8_t SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

/*
 * Inverse Sboxs
 */
__constant__ uint8_t INV_SBOX[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};

/**
 *
 * https://en.wikipedia.org/wiki/Finite_field_arithmetic
 * Multiply two numbers in the GF(2^8) finite field defined
 * by the polynomial x^8 + x^4 + x^3 + x + 1 = 0
 * We do use mul2(int8_t a) but not mul(uint8_t a, uint8_t b)
 * just in order to get a higher speed.
 */
__device__ inline uint8_t mul2(uint8_t a) {
    return (a&0x80) ? ((a<<1)^0x1b) : (a<<1);
}

/**
 * @purpose:    ShiftRows
 * @descrption:
 *  Row0: s0  s4  s8  s12   <<< 0 byte
 *  Row1: s1  s5  s9  s13   <<< 1 byte
 *  Row2: s2  s6  s10 s14   <<< 2 bytes
 *  Row3: s3  s7  s11 s15   <<< 3 bytes
 */
__device__ void shift_rows(uint8_t *state) {
    uint8_t temp;
    // row1
    temp        = *(state+1);
    *(state+1)  = *(state+5);
    *(state+5)  = *(state+9);
    *(state+9)  = *(state+13);
    *(state+13) = temp;
    // row2
    temp        = *(state+2);
    *(state+2)  = *(state+10);
    *(state+10) = temp;
    temp        = *(state+6);
    *(state+6)  = *(state+14);
    *(state+14) = temp;
    // row3
    temp        = *(state+15);
    *(state+15) = *(state+11);
    *(state+11) = *(state+7);
    *(state+7)  = *(state+3);
    *(state+3)  = temp;
}

/**
 * @purpose:    Inverse ShiftRows
 * @description
 *  Row0: s0  s4  s8  s12   >>> 0 byte
 *  Row1: s1  s5  s9  s13   >>> 1 byte
 *  Row2: s2  s6  s10 s14   >>> 2 bytes
 *  Row3: s3  s7  s11 s15   >>> 3 bytes
 */
__device__ void inv_shift_rows(uint8_t *state) {
    uint8_t temp;
    // row1
    temp        = *(state+13);
    *(state+13) = *(state+9);
    *(state+9)  = *(state+5);
    *(state+5)  = *(state+1);
    *(state+1)  = temp;
    // row2
    temp        = *(state+14);
    *(state+14) = *(state+6);
    *(state+6)  = temp;
    temp        = *(state+10);
    *(state+10) = *(state+2);
    *(state+2)  = temp;
    // row3
    temp        = *(state+3);
    *(state+3)  = *(state+7);
    *(state+7)  = *(state+11);
    *(state+11) = *(state+15);
    *(state+15) = temp;
}



__device__ void Paes_encrypt_256(const uint8_t *roundkeys, const uint8_t *plaintext, uint8_t *ciphertext) {

    uint8_t tmp[16], t;
    uint8_t i, j;

    // Initial AddRoundKey
    for (i = 0; i < AES_BLOCK_SIZE; ++i) {
        *(ciphertext + i) = *(plaintext + i) ^ *roundkeys++;
    }

    // 13 rounds (AES-256 has 14 rounds total, excluding the last round)
    for (j = 1; j < AES_ROUNDS_256; ++j) {

        // SubBytes
        for (i = 0; i < AES_BLOCK_SIZE; ++i) {
            *(tmp + i) = SBOX[*(ciphertext + i)];
        }

        // ShiftRows
        shift_rows(tmp);

        // MixColumns
        for (i = 0; i < AES_BLOCK_SIZE; i += 4) {
            t = tmp[i] ^ tmp[i + 1] ^ tmp[i + 2] ^ tmp[i + 3];
            ciphertext[i]     = mul2(tmp[i] ^ tmp[i + 1]) ^ tmp[i] ^ t;
            ciphertext[i + 1] = mul2(tmp[i + 1] ^ tmp[i + 2]) ^ tmp[i + 1] ^ t;
            ciphertext[i + 2] = mul2(tmp[i + 2] ^ tmp[i + 3]) ^ tmp[i + 2] ^ t;
            ciphertext[i + 3] = mul2(tmp[i + 3] ^ tmp[i]) ^ tmp[i + 3] ^ t;
        }

        // AddRoundKey
        for (i = 0; i < AES_BLOCK_SIZE; ++i) {
            *(ciphertext + i) ^= *roundkeys++;
        }
    }

    // Final round (no MixColumns)
    for (i = 0; i < AES_BLOCK_SIZE; ++i) {
        *(ciphertext + i) = SBOX[*(ciphertext + i)];
    }

    shift_rows(ciphertext);

    // AddRoundKey
    for (i = 0; i < AES_BLOCK_SIZE; ++i) {
        *(ciphertext + i) ^= *roundkeys++;
    }
}


__global__ void GCTRKernel(const uint8_t* ICB, const uint8_t* val, int numAESBlocks, uint8_t* result, const uint8_t* key, const uint8_t* roundkeys) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;

    if (idx < numAESBlocks) {
        uint8_t counter[16];
        memcpy(counter, ICB, 16);

        // Increment counter
        for (int k = 0; k < idx; ++k) {
            for (int i = 15; i >= 12; --i) {
                if (++counter[i] != 0) break;
            }
        }

        // AES encryption
        uint8_t encryptedCounter[16];
        Paes_encrypt_256(roundkeys, counter, encryptedCounter);

        // XOR with val and store result
        for (int i = 0; i < 16; ++i) {
            result[idx * 16 + i] = encryptedCounter[i] ^ val[idx * 16 + i];
        }
    }
}

__global__ void GHASHKernel( uint8_t *H, uint8_t *val,int Valsize, int increment ,uint8_t *result) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    int start = idx*increment;
    int end = start + increment < Valsize? start + increment : Valsize;

    if (start < Valsize) {
        uint8_t partialResults[16] = {0};
        uint8_t intermediate[16];
        uint8_t intermediate2[16];
        int blockSize =(Valsize + 15) / 16;

        for (int i = start; i < end; ++i) {
            gf128Power(H,  blockSize- i, intermediate);
            gf128Multiply(&val[i*16],intermediate,intermediate2);

            for (int j = 0; j < 16; ++j) {
                partialResults[j] = partialResults[j] ^ intermediate2[j];
            }
        }

        // Store the result
        for (int i = 0; i < 16; ++i) {
            result[i] ^= partialResults[i];
        }
    }
}

__device__ void gf128Multiply(uint8_t *X, uint8_t *Y, uint8_t *result) {

    uint8_t Z0[16] = {0};
    uint8_t V0[16];
    uint8_t  R[16] =  {0xe1,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    for (int i = 0; i < 16; ++i) {
        V0[i] = Y[i];
    }

    // Iterate over all 128 bits
    for (int i = 0; i < 128; ++i) {
        // If the i-th bit of X is set, XOR Z0 with V0
        if ((X[i / 8] >> (7 - (i % 8))) & 1) {
            for (int j = 0; j < 16; ++j) {
                Z0[j] ^= V0[j];
            }
        }

        // Check the least significant bit of V0
        bool lsb = (V0[15] & 1) != 0;

        // Right shift V0
        for (int j = 15; j > 0; --j) {
            V0[j] = (V0[j] >> 1) | ((V0[j - 1] & 1) << 7);
        }
        V0[0] >>= 1;

        // If lsb is set, XOR V0 with R
        if (lsb) {
            for (int j = 0; j < 16; ++j) {
                V0[j] ^= R[j];
            }
        }
    }

    // Copy Z0 into the result
    for (int i = 0; i < 16; ++i) {
        result[i] = Z0[i];
    }
}

__device__ void gf128Power(uint8_t *H, int power, uint8_t *result) {
    // Compute H^power in GF(2^128)
    uint8_t ComputedResult[] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01}; // Identity element: all zeros
    // Set least significant byte to 1 (H^0 = 1)

    if (power == 0) {
        for (int i = 0; i < 16; ++i) {
            result[i] = ComputedResult[i];
        }
        return;
    }

    // Initialize result with H (H^1 = H)
    for (int i = 0; i < 16; ++i) {
        ComputedResult[i] = H[i];
    }

    // Multiply H with itself power-1 times
    uint8_t intermediateResult[16];
    for (int i = 1; i < power; ++i) {
        gf128Multiply(ComputedResult, H, intermediateResult);
        for (int j = 0; j < 16; ++j) {
            ComputedResult[j] = intermediateResult[j];
        }
    }

    // Copy final result
    for (int i = 0; i < 16; ++i) {
        result[i] = ComputedResult[i];
    }
}