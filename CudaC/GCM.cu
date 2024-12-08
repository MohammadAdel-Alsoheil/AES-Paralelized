#include <iostream>
#include <iomanip>
#include <vector>
#include "kernelsGCM.h"
#include "aes.h"
#include <cstdint>
#include <cmath>
#include <cstring>
#include "Utils.h"
#include "Ghash.h"
#include <chrono>


using ByteVector = std::vector<unsigned char>;
using namespace chrono;

class GCM {
private:
    uint8_t key[32];
    uint8_t IV[12];
    ByteVector AAD;

    void prepareCounter(uint8_t *counter, const uint8_t *IV) {
        // Assuming `counter` has been pre-allocated with at least 16 bytes
        memcpy(counter, IV, 12); // Copy the 12-byte IV into the counter
        counter[12] = 0x00; // Append 4 additional bytes
        counter[13] = 0x00;
        counter[14] = 0x00;
        counter[15] = 0x01;
    }

    void incrementCounter(uint8_t *counter) {
        // Increment the last 4 bytes, which represent the counter value
        for (int i = 15; i >= 12; --i) {
            if (++counter[i] != 0) {
                // Increment and check for overflow
                break; // Stop if no overflow
            }
        }
    }


    ByteVector encodeLength(uint64_t len) {
        ByteVector encoded(8, 0);
        for (int i = 7; i >= 0; --i) {
            encoded[i] = len & 0xFF;
            len >>= 8;
        }
        return encoded;
    }

    ByteVector padC(ByteVector C, int u, int v, int sizeOfC, int sizeOfA) {
        ByteVector res;

        // Step 1: Add A to the result
        res.insert(res.end(), AAD.begin(), AAD.end());

        // Step 2: Add 0^v (v/8 bytes for A padding)
        int paddingVBytes = v / 8;
        res.insert(res.end(), paddingVBytes, 0x00);

        // Step 3: Add C to the result
        res.insert(res.end(), C.begin(), C.end());

        // Step 4: Add 0^u (u/8 bytes for C padding)
        int paddingUBytes = u / 8;
        res.insert(res.end(), paddingUBytes, 0x00);

        // Step 5: Encode len(A) as a 64-bit value and append
        ByteVector lenA64 = encodeLength(sizeOfA); // Length of A in bits

        res.insert(res.end(), lenA64.begin(), lenA64.end());

        // Step 6: Encode len(C) as a 64-bit value and append
        ByteVector lenC64 = encodeLength(sizeOfC);

        res.insert(res.end(), lenC64.begin(), lenC64.end());


        return res;
    }

public:
    pair<ByteVector, ByteVector> encrypt(uint8_t *key, uint8_t *IV, ByteVector AAD, int AADsize, uint8_t *plainText,
                                         int plaintextSize) {
        // Key and IV setup

        memcpy(this->key, key, 32);
        memcpy(this->IV, IV, 12);
        this->AAD = AAD;
        int numAESBlocks = (plaintextSize + 15) / 16; // similar to ceil(pSize/16) but better efficiency
        int threadsPerBlock = 256;
        int blocksPerGrid = (numAESBlocks + threadsPerBlock - 1) / threadsPerBlock;
        int AddedPaddingSize = plaintextSize;
        // Device memory
        uint8_t *d_plaintext, *d_result, *d_ICB, *d_key, *d_roundkeys;
        cudaMalloc(&d_plaintext, plaintextSize);
        cudaMalloc(&d_result, numAESBlocks * 16);
        cudaMalloc(&d_ICB, 16);
        cudaMalloc(&d_key, 32);
        cudaMallocManaged(&d_roundkeys, AES_ROUND_KEY_SIZE_256);

        // Key schedule
        uint8_t roundkeys[AES_ROUND_KEY_SIZE_256];
        aes_key_schedule_256(key, roundkeys);

        //prepare H
        uint8_t H[16];
        uint8_t zeros[16] = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };
        aes_encrypt_256(roundkeys, zeros, H); // correct


        // Copy data to device
        cudaMemcpy(d_plaintext, plainText, plaintextSize, cudaMemcpyHostToDevice);
        cudaMemcpy(d_key, key, 32, cudaMemcpyHostToDevice);
        cudaMemcpy(d_roundkeys, roundkeys, AES_ROUND_KEY_SIZE_256, cudaMemcpyHostToDevice);
        // Prepare counter
        uint8_t ICB[16];
        prepareCounter(ICB, IV);
        incrementCounter(ICB);
        cudaMemcpy(d_ICB, ICB, 16, cudaMemcpyHostToDevice);


        // Launch GCTR kernel for plaintext encryption
        GCTRKernel<<<blocksPerGrid, threadsPerBlock>>>(d_ICB, d_plaintext, numAESBlocks, d_result, d_key, d_roundkeys);
        cudaDeviceSynchronize();

        // Copy encrypted result back to host
        ByteVector encryptedText(numAESBlocks * 16);
        cudaMemcpy(encryptedText.data(), d_result, numAESBlocks * 16, cudaMemcpyDeviceToHost);

        while (AddedPaddingSize < encryptedText.size()) {
            encryptedText.pop_back();
            AddedPaddingSize++;
        }

        // Calculate sizes in bits
        int sizeOfCinBits = encryptedText.size() * 8;
        int sizeOfAADinBits = AADsize * 8;

        int u = (128 * ceil((double) sizeOfCinBits / 128)) - sizeOfCinBits;
        int v = (128 * ceil((double) sizeOfAADinBits / 128)) - sizeOfAADinBits;


        int increment = 32;
        ByteVector padded = padC(encryptedText, u, v, sizeOfCinBits, sizeOfAADinBits); //correct // checked
        uint8_t *padded_d;
        uint8_t *d_S;
        uint8_t *d_H;
        cudaMalloc(&d_S, 16);
        cudaMalloc(&d_H, 16);
        cudaMalloc(&padded_d, padded.size());
        cudaMemset(d_S, 0, 16);
        cudaMemcpy(d_H,H, 16, cudaMemcpyHostToDevice);
        cudaMemcpy(padded_d, padded.data(), padded.size(),cudaMemcpyHostToDevice);
        GHASHKernel<<<blocksPerGrid,threadsPerBlock>>>(d_H,padded_d,padded.size(),increment,d_S);


        // Launch GCTR kernel for tag generation
        prepareCounter(ICB, IV);
        cudaMemcpy(d_ICB, ICB, 16, cudaMemcpyHostToDevice);
        ByteVector T(16);
        GCTRKernel<<<blocksPerGrid, threadsPerBlock>>>(d_ICB, d_S, 1, d_result, d_key, d_roundkeys);

        // Copy tag back to host
        cudaMemcpy(T.data(), d_result, 16, cudaMemcpyDeviceToHost);

        // Free device memory
        cudaFree(d_plaintext);
        cudaFree(d_result);
        cudaFree(d_ICB);
        cudaFree(d_key);
        cudaFree(d_roundkeys);
        cudaFree(d_S);
        cudaFree(padded_d);


        return std::make_pair(encryptedText, T);
    }

    ByteVector decrypt(uint8_t *key, uint8_t *IV, ByteVector AAD, int AADsize, uint8_t *cipherText,
                       int cipherTextSize, ByteVector T) {
        // Key and IV setup

        memcpy(this->key, key, 32);
        memcpy(this->IV, IV, 12);
        this->AAD = AAD;
        int numAESBlocks = (cipherTextSize + 15) / 16; // similar to ceil(pSize/16) but better efficiency
        int threadsPerBlock = 256;
        int blocksPerGrid = (numAESBlocks + threadsPerBlock - 1) / threadsPerBlock;
        int AddedPaddingSize = cipherTextSize;
        // Device memory
        uint8_t *d_ciphertext, *d_result, *d_ICB, *d_key, *d_roundkeys;
        cudaMalloc(&d_ciphertext, cipherTextSize);
        cudaMalloc(&d_result, numAESBlocks * 16);
        cudaMalloc(&d_ICB, 16);
        cudaMalloc(&d_key, 32);
        cudaMallocManaged(&d_roundkeys, AES_ROUND_KEY_SIZE_256);

        // Key schedule
        uint8_t roundkeys[AES_ROUND_KEY_SIZE_256];
        aes_key_schedule_256(key, roundkeys);

        //prepare H
        uint8_t H[16];
        uint8_t zeros[16] = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };
        aes_encrypt_256(roundkeys, zeros, H); // correct


        // Copy data to device
        cudaMemcpy(d_ciphertext, cipherText, cipherTextSize, cudaMemcpyHostToDevice);
        cudaMemcpy(d_key, key, 32, cudaMemcpyHostToDevice);
        cudaMemcpy(d_roundkeys, roundkeys, AES_ROUND_KEY_SIZE_256, cudaMemcpyHostToDevice);
        // Prepare counter
        uint8_t ICB[16];
        prepareCounter(ICB, IV);
        incrementCounter(ICB);
        cudaMemcpy(d_ICB, ICB, 16, cudaMemcpyHostToDevice);


        // Launch GCTR kernel for plaintext encryption
        GCTRKernel<<<blocksPerGrid, threadsPerBlock>>>(d_ICB, d_ciphertext, numAESBlocks, d_result, d_key, d_roundkeys);
        cudaDeviceSynchronize();

        // Copy encrypted result back to host
        ByteVector plainText(numAESBlocks * 16);
        cudaMemcpy(plainText.data(), d_result, numAESBlocks * 16, cudaMemcpyDeviceToHost);

        while (AddedPaddingSize < plainText.size()) {
            plainText.pop_back();
            AddedPaddingSize++;
        }


        // Calculate sizes in bits
        int sizeOfCinBits = cipherTextSize * 8;
        int sizeOfAADinBits = AADsize * 8;

        int u = (128 * ceil((double) sizeOfCinBits / 128)) - sizeOfCinBits;
        int v = (128 * ceil((double) sizeOfAADinBits / 128)) - sizeOfAADinBits;


        // Pad AAD and ciphertext
        ByteVector Hv;
        for (int i = 0; i < 16; ++i) {
            Hv.push_back(H[i]);
        }
        // copy cipherText to a ByteVector
        ByteVector encryptedText;
        for (int i = 0; i < cipherTextSize; ++i) {
            encryptedText.push_back(cipherText[i]);
        }

        int increment = 32;
        ByteVector padded = padC(encryptedText, u, v, sizeOfCinBits, sizeOfAADinBits); //correct // checked
        uint8_t *padded_d;
        uint8_t *d_S;
        uint8_t *d_H;
        cudaMalloc(&d_S, 16);
        cudaMalloc(&d_H, 16);
        cudaMalloc(&padded_d, padded.size());
        cudaMemset(d_S, 0, 16);
        cudaMemcpy(d_H,H, 16, cudaMemcpyHostToDevice);
        cudaMemcpy(padded_d, padded.data(), padded.size(),cudaMemcpyHostToDevice);
        GHASHKernel<<<blocksPerGrid,threadsPerBlock>>>(d_H,padded_d,padded.size(),increment,d_S);


        // Launch GCTR kernel for tag generation
        prepareCounter(ICB, IV);
        cudaMemcpy(d_ICB, ICB, 16, cudaMemcpyHostToDevice);
        ByteVector Tprime(16);
        GCTRKernel<<<blocksPerGrid, threadsPerBlock>>>(d_ICB, d_S, 1, d_result, d_key, d_roundkeys);

        // Copy tag back to host
        cudaMemcpy(Tprime.data(), d_result, 16, cudaMemcpyDeviceToHost);

        for (int i = 0; i < 16; ++i) {
            if (T[i] != Tprime[i]) {
                throw invalid_argument("There is no integrity between T and Tprime");
            }
        }


        // Free device memory
        cudaFree(d_ciphertext);
        cudaFree(d_result);
        cudaFree(d_ICB);
        cudaFree(d_key);
        cudaFree(d_roundkeys);
        cudaFree(d_S);


        return plainText;
    }
};


int main() {
    // Key (16 bytes)
    uint8_t Key[32] = {
        0x4C, 0x97, 0x3D, 0xBC, 0x73, 0x64, 0x62, 0x16,
        0x74, 0xF8, 0xB5, 0xB8, 0x9E, 0x5C, 0x15, 0x51,
        0x1F, 0xCE, 0xD9, 0x21, 0x64, 0x90, 0xFB, 0x1C,
        0x1A, 0x2C, 0xAA, 0x0F, 0xFE, 0x04, 0x07, 0xE5
    };

    // P (Plaintext, 63 bytes)
    uint8_t P[2000000];
    for(int i =0;i<2000000;i++){
        P[i] = 0x00;
    }

    // uint8_t P[63] = {
    //     0x08, 0x00, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14,
    //     0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
    //     0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24,
    //     0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C,
    //     0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34,
    //     0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C,
    //     0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44,
    //     0x45, 0x46, 0x47, 0x48, 0x49, 0x00, 0x08
    // };

    // IV (Initialization Vector, 12 bytes)
    uint8_t IV[12] = {
        0x7A, 0xE8, 0xE2, 0xCA, 0x4E, 0xC5, 0x00, 0x01,
        0x2E, 0x58, 0x49, 0x5C
    };

    // A (Associated Data, 20 bytes)
    ByteVector A = {
        0x68, 0xF2, 0xE7, 0x76, 0x96, 0xCE, 0x7A, 0xE8,
        0xE2, 0xCA, 0x4E, 0xC5, 0x88, 0xE5, 0x4D, 0x00,
        0x2E, 0x58, 0x49, 0x5C
    };
    int Asize = A.size();
    int Psize = sizeof(P) / sizeof(P[0]);

    GCM gcm;

    ByteVector plainText;
    for (int i = 0; i < Psize; ++i) {
        plainText.push_back(P[i]);
    }
    auto startEnc = high_resolution_clock::now(); // start time
    //cout << "Plaintext: " << Utils::bytesToHex(plainText) << endl;
    pair<ByteVector, ByteVector> ciphertext = gcm.encrypt(Key, IV, A, Asize, P, Psize);
    auto endEnc = high_resolution_clock::now(); // end time
    auto durationEnc = duration_cast<microseconds>(endEnc - startEnc).count();
    //std::cout << "CipherText: " << Utils::bytesToHex(ciphertext.first) << std::endl;
    //std::cout << "Tag: " << Utils::bytesToHex(ciphertext.second) << std::endl;
    std::cout << "Encryption of a " + std::to_string(Psize) + " bytes took "
            + std::to_string(durationEnc) + " microseconds" << std::endl;
    auto startDec = high_resolution_clock::now(); // start time
    ByteVector deciphered = gcm.decrypt(Key, IV, A, A.size(), ciphertext.first.data(), ciphertext.first.size(),
                                        ciphertext.second);
    auto endDec = high_resolution_clock::now(); // end time
    auto durationDec = duration_cast<microseconds>(endDec - startDec).count();
    //cout << "Decrypted Text: " + Utils::bytesToHex(deciphered) << "\n";
    std::cout << "Decryption of a " + std::to_string(ciphertext.first.size()) + " bytes took "
            + std::to_string(durationDec) + " microseconds" << std::endl;

    return 0;
}

