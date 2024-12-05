#include <iostream>
#include <vector>
#include <cmath>
#include <string>
#include <stdexcept>
#include <bitset>
#include "AES.cpp"
#include "Ghash.h"
using namespace Utils;


class GCMCuda {
private:
    ByteVector key;
    ByteVector IV;
    ByteVector AAD;

    void prepareCounter(ByteVector& counter, const ByteVector& IV) {
        // If IV is 96 bits, append 0x00000001 to form J0
        if (IV.size() == 12) {
            counter = IV;
            counter.push_back(0x00);
            counter.push_back(0x00);
            counter.push_back(0x00);
            counter.push_back(0x01);
        } else {
            throw invalid_argument("IV must be 96 bits (12 bytes) in this implementation.");
        }
    }



    void incrementCounter(ByteVector& counter) {
        for (int i = 15; i >= 12; --i) { // Last 4 bytes represent the counter
            if (++counter[i] != 0) {
                break; // Stop incrementing if no overflow
            }
        }
    }

    void PincrementCounter(unsigned char* counter){
        for (int i = 15; i >= 12; --i) { // Last 4 bytes represent the counter
            if (++counter[i] != 0) {
                break; // Stop incrementing if no overflow
            }
        }
    }

    ByteVector ArrayToByteVector(unsigned char A[]){
        ByteVector res;
        int size = sizeof(arr) / sizeof(arr[0]);
        for(int i = 0;i<size;++i){
            res.push_back(A[i]);
        }
        return res;
    }


    vector<ByteVector> GCTR(ByteVector ICB, ByteVector val) {
        
        vector<ByteVector> X = nest(val,16);
        ByteVector result;  

        // Allocate memory on the device
        unsigned char *d_val, *d_ICB, *d_result, *d_key;
        cudaMalloc(&d_val, val.size());
        cudaMalloc(&d_ICB, ICB.size());
        cudaMalloc(&d_result, result.size());
        cudaMalloc(&d_key, key.size());

        // Copy data to the device
        cudaMemcpy(d_val, val.data(), val.size(), cudaMemcpyHostToDevice);
        cudaMemcpy(d_ICB, ICB.data(), ICB.size(), cudaMemcpyHostToDevice);
        cudaMemcpy(d_key, key.data(), key.size(), cudaMemcpyHostToDevice);

        // Launch the kernel
        int threadsPerBlock = 256;
        int numBlocksPerGrid = (numBlocks + threadsPerBlock - 1) / threadsPerBlock;
        GCTRKernel<<<numBlocksPerGrid, threadsPerBlock>>>(d_ICB, d_val, numBlocks, d_result, d_key);

        // Copy the result back to the host
        cudaMemcpy(result.data(), d_result, result.size(), cudaMemcpyDeviceToHost);

        // Free device memory
        cudaFree(d_val);
        cudaFree(d_ICB);
        cudaFree(d_result);
        cudaFree(d_key);

        // Convert the flat result into a vector of ByteVectors
        vector<ByteVector> res(numBlocks, ByteVector(blockSize));
        for (int i = 0; i < numBlocks; ++i) {
            std::copy(result.begin() + i * blockSize, result.begin() + (i + 1) * blockSize, res[i].begin());
        }

        return res;
    }


    __global__ void GCTRKernel(const unsigned char* ICB, const unsigned char* val, int numBlocks, const unsigned char* result){
        
        int idx = blockIdx.x * blockDim.x + threadIdx.x;

        if (idx < numBlocks) {

            unsigned char counter[16];
            memcpy(counter, ICB, 16);
          
            // Encrypt the counter
            unsigned char encryptedCounter[16];
            AES aes;  
            ByteVector calKey = aes.encrypt( ArrayToByteVector(counter), key);
            ByteVector X = ArrayToByteVector(val);
            ByteVector Partialres =  xorF(X,calKey);

            unsigned char *PartialresCopy;
            cudaMalloc(&PartialresCopy, Partialres.size());
            cudaMemcpy(Partialres.data(), PartialresCopy, result.size(), cudaMemcpyDeviceToHost);

            //increment counter
            for(int k = 0;k<idx+1;++k){
                for (int i = 0; i < 4; ++i) {
                    counter[15 - i] += idx & 0xFF;  // Increment based on thread index
                }
            }

             cudaFree(PartialresCopy);
            
        }
    }

    __global__ void GHASHKernel(const unsigned char* val, int numBlocks, const unsigned char* H, unsigned char* result) {
        extern __shared__ unsigned char sharedMemory[];

        int idx = blockIdx.x * blockDim.x + threadIdx.x;

        // Shared memory for intermediate results
        unsigned char* sharedY = &sharedMemory[threadIdx.x * 16];

        // Each thread processes one block
        if (idx < numBlocks) {
            const unsigned char* block = &val[idx * 16];
            unsigned char intermediate[16] = {0};

            // XOR with current Y
            for (int i = 0; i < 16; ++i) {
                intermediate[i] = sharedY[i] ^ block[i];
            }

            // Perform GF(128) multiplication
            Ghash::gf128Multiply(intermediate, H, sharedY);  // Example GF(128) multiplication
        }

        // Synchronize all threads in the block
        __syncthreads();

        // Reduction: Combine results into a single Y0
        for (int offset = 1; offset < blockDim.x; offset *= 2) {
            if (threadIdx.x % (2 * offset) == 0 && idx + offset < numBlocks) {
                for (int i = 0; i < 16; ++i) {
                    sharedY[i] ^= sharedY[i + offset * 16];
                }
            }
            __syncthreads();
        }

        // Write the final result for this block back to global memory
        if (threadIdx.x == 0) {
            memcpy(result, sharedY, 16);
        }
    }


    ByteVector GHASH(ByteVector val, ByteVector H) {
        int blockSize = 16;
        int numBlocks = (val.size() + blockSize - 1) / blockSize;

        // Prepare input
        ByteVector result(blockSize, 0x00);

        // Allocate device memory
        unsigned char *d_val, *d_H, *d_result;
        cudaMalloc(&d_val, val.size());
        cudaMalloc(&d_H, H.size());
        cudaMalloc(&d_result, blockSize);

        // Copy data to device
        cudaMemcpy(d_val, val.data(), val.size(), cudaMemcpyHostToDevice);
        cudaMemcpy(d_H, H.data(), H.size(), cudaMemcpyHostToDevice);

        // Launch the kernel
        int threadsPerBlock = 256;
        int sharedMemSize = threadsPerBlock * blockSize;
        int blocksPerGrid = (numBlocks + threadsPerBlock - 1) / threadsPerBlock;
        GHASHKernel<<<blocksPerGrid, threadsPerBlock, sharedMemSize>>>(d_val, numBlocks, d_H, d_result);

        // Copy result back to host
        cudaMemcpy(result.data(), d_result, blockSize, cudaMemcpyDeviceToHost);

        // Free device memory
        cudaFree(d_val);
        cudaFree(d_H);
        cudaFree(d_result);

        return result;
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


    ByteVector encodeLength(uint64_t len) {
        ByteVector encoded(8, 0);
        for (int i = 7; i >= 0; --i) {
            encoded[i] = len & 0xFF;
            len >>= 8;
        }
        return encoded;
    }


public:


    // for psuedo code reference https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
     pair<ByteVector, ByteVector> encrypt(const ByteVector key,  const ByteVector IV, const ByteVector AAD,ByteVector P) {
        this->AAD= AAD;
        this->IV = IV;
        this->key = key;

        AES aes;

        ByteVector H = aes.encrypt(ByteVector(16, 0x00), key);


        ByteVector J0;
        prepareCounter(J0, this->IV);


        incrementCounter(J0);
        vector<ByteVector> C = GCTR(J0, P);
        ByteVector newC = flatten(C);
        newC.pop_back();
        int sizeOfCinBits = newC.size()*8;
        int sizeofAADinBits = AAD.size()*8;


        int u = (128*ceil((double) sizeOfCinBits/128)) - sizeOfCinBits;
        int v = (128*ceil((double) sizeofAADinBits/128)) - sizeofAADinBits;


        ByteVector S = GHASH(padC(newC,u,v, sizeOfCinBits,sizeofAADinBits ), H);
        prepareCounter(J0, this->IV);
        vector<ByteVector> T = GCTR(J0,S);
        ByteVector newT = flatten(T);



        return { newC, newT };
    }

    __global__ void encryptKernel(ByteVector key, ByteVector IV, ByteVector AAD, ByteVector P, ByteVector* C, ByteVector* T){
        int idx = threadIdx.x + blockIdx.x * blockDim.x;

        __shared__ ByteVector H;
        __shared__ vector<ByteVector>;
        __shared__ ByteVector J0;

        if(idx==0){
            AES aes;
            H = aes.encrypt(ByteVector(16, 0x00), key); //prepare H
            prepareCounter(J0, this->IV);
        }
        __syncthreads();

            // Each thread works on one block of the plaintext P
            if (idx < P.size() / 16) {
            
            }
    }


};

int main(){
    // Key (16 bytes)
    ByteVector Key = {
            0x4C, 0x97, 0x3D, 0xBC, 0x73, 0x64, 0x62, 0x16,
            0x74, 0xF8, 0xB5, 0xB8, 0x9E, 0x5C, 0x15, 0x51,
            0x1F, 0xCE, 0xD9, 0x21, 0x64, 0x90, 0xFB, 0x1C,
            0x1A, 0x2C, 0xAA, 0x0F, 0xFE, 0x04, 0x07, 0xE5
    };
    // P (Plaintext, 64 bytes)
    ByteVector P = {
            0x08, 0x00, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14,
            0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24,
            0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C,
            0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34,
            0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C,
            0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44,
            0x45, 0x46, 0x47, 0x48, 0x49, 0x00, 0x08
    };

    // IV (Initialization Vector, 12 bytes)
    ByteVector IV = {
            0x7A, 0xE8, 0xE2, 0xCA, 0x4E, 0xC5, 0x00, 0x01,
            0x2E, 0x58, 0x49, 0x5C
    };

    // A (Associated Data, 20 bytes)
    ByteVector A = {
            0x68, 0xF2, 0xE7, 0x76, 0x96, 0xCE, 0x7A, 0xE8,
            0xE2, 0xCA, 0x4E, 0xC5, 0x88, 0xE5, 0x4D, 0x00,
            0x2E, 0x58, 0x49, 0x5C
    };


    GCMCuda gcm;
    pair<ByteVector, ByteVector> res = gcm.encrypt(Key, IV, A,P);
    cout << "Cipher Text: " + bytesToHex(res.first) << "\n";
    cout << "Added Tag: " + bytesToHex(res.second) << "\n";

    return 0;
}
