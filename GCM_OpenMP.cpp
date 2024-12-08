////
//// Created by ahmad on 12/5/2024.
////
//#include <iostream>
//#include <vector>
//#include <cmath>
//#include <string>
//#include <stdexcept>
//#include "AES.cpp"
//#include "Ghash.h"
//#include <chrono>
//#include <omp.h>
//
//using namespace Utils;
//
//
//class GCM_OpenMP {
//private:
//    ByteVector key;
//    ByteVector IV;
//    ByteVector AAD;
//
//    void prepareCounter(ByteVector& counter, const ByteVector& IV) {
//        // If IV is 96 bits, append 0x00000001 to form J0
//        if (IV.size() == 12) {
//            counter = IV;
//            counter.push_back(0x00);
//            counter.push_back(0x00);
//            counter.push_back(0x00);
//            counter.push_back(0x01);
//        } else {
//            throw invalid_argument("IV must be 96 bits (12 bytes) in this implementation.");
//        }
//    }
//
//
//
//    void incrementCounter(ByteVector& counter) {
//        for (int i = 15; i >= 12; --i) { // Last 4 bytes represent the counter
//            if (++counter[i] != 0) {
//                break; // Stop incrementing if no overflow
//            }
//        }
//    }
//
//    vector<ByteVector> GCTR(ByteVector ICB, ByteVector val) {
//        ByteVector CB = ICB;
//        vector<ByteVector> X = nest(val, 16);
//        vector<ByteVector> res(X.size());
//
//#pragma omp parallel
//        {
//            AES aes(key); // Thread-local AES instance
//            ByteVector CB_local;
//#pragma omp for
//            for (int i = 0; i < X.size(); ++i) {
//                CB_local = CB;
//                for (int j = 0; j < i; ++j) { // Increment local counter to the right position
//                    incrementCounter(CB_local);
//                }                ByteVector Y = xorF(aes.encrypt(CB_local), X[i]);
//                res[i] = Y;
//            }
//        }
//        return res;
//    }
//    ByteVector gf128Power(ByteVector H, int power) {
//        if (power == 0) {
//            // Return the identity element in GF(2^128)
//            ByteVector identity = ByteVector(16, 0x00);
//            identity[15] = 0x01;
//            return identity;
//        }
//
//        ByteVector result = H; // Start with H
//        for (int i = 1; i < power; ++i) {
//            result = Ghash::gf128Multiply(result, H);
//        }
//        return result;
//    }
//
//// Parallelized GHASH
//    ByteVector GHASH(ByteVector val, ByteVector H, int degree_of_parallelism = 4) {
//        vector<ByteVector> X = nest(val, 16); // Break the input into 16-byte blocks
//        int n = X.size();
//
//        // Partial tags for each parallel stream
//        std::vector<ByteVector> partialTags(degree_of_parallelism, ByteVector(16, 0x00));
//
//        // Compute j = H^degree_of_parallelism for scaling
//        ByteVector j = gf128Power(H, degree_of_parallelism);
//
//        // Parallel computation of independent streams
//#pragma omp parallel for num_threads(degree_of_parallelism)
//        for (int t = 0; t < degree_of_parallelism; ++t) {
//            ByteVector localTag = ByteVector(16, 0x00);
//            ByteVector currentH = gf128Power(j, 0); // Initial power of H for this stream
//            cout << Utils::bytesToHex(currentH) << endl;
//            int pow =1;
//            for (int i = t; i < n; i += degree_of_parallelism) {
//                localTag = xorF(localTag, Ghash::gf128Multiply(X[i], currentH));
//                currentH =gf128Power(j, pow++);
//            }
//            partialTags[t] = localTag;
//        }
//
//        // Combine partial results
//        ByteVector finalTag = ByteVector(16, 0x00);
//        ByteVector currentJ = ByteVector(16, 0x00); // Start with j^0 = 1
//
//        cout << Utils::bytesToHex(Ghash::gf128Multiply(H,Ghash::gf128Multiply(H,H)))  <<   endl;
//
//        for (int t = 0; t < degree_of_parallelism; ++t) {
//            cout << endl<< Utils::bytesToHex(gf128Power(H,t)) << " " << t <<  endl;
//
//            finalTag = xorF(finalTag, Ghash::gf128Multiply(partialTags[t], gf128Power(j,t)));
//        }
//
//
//        return finalTag;
//    }
//    ByteVector padC(ByteVector C, int u, int v, int sizeOfC, int sizeOfA) {
//        ByteVector res;
//
//        // Step 1: Add A to the result
//        res.insert(res.end(), AAD.begin(), AAD.end());
//
//        // Step 2: Add 0^v (v/8 bytes for A padding)
//        int paddingVBytes = v / 8;
//        res.insert(res.end(), paddingVBytes, 0x00);
//
//        // Step 3: Add C to the result
//        res.insert(res.end(), C.begin(), C.end());
//
//        // Step 4: Add 0^u (u/8 bytes for C padding)
//        int paddingUBytes = u / 8;
//        res.insert(res.end(), paddingUBytes, 0x00);
//
//        // Step 5: Encode len(A) as a 64-bit value and append
//        ByteVector lenA64 = encodeLength(sizeOfA); // Length of A in bits
//
//        res.insert(res.end(), lenA64.begin(), lenA64.end());
//
//        // Step 6: Encode len(C) as a 64-bit value and append
//        ByteVector lenC64 = encodeLength(sizeOfC);
//
//        res.insert(res.end(), lenC64.begin(), lenC64.end());
//
//        return res;
//    }
//
//
//    ByteVector encodeLength(uint64_t len) {
//        ByteVector encoded(8, 0);
//        for (int i = 7; i >= 0; --i) {
//            encoded[i] = len & 0xFF;
//            len >>= 8;
//        }
//        return encoded;
//    }
//
//
//public:
//
//
//    // for psuedo code reference https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
//    pair<ByteVector, ByteVector> encrypt(const ByteVector key,  const ByteVector IV, const ByteVector AAD,ByteVector P) {
//        this->AAD= AAD;
//        this->IV = IV;
//        this->key = key;
//
//        AES aes(key);
//
//        ByteVector H = aes.encrypt(ByteVector(16, 0x00));
//
//
//        ByteVector J0;
//        prepareCounter(J0, this->IV);
//
//
//        incrementCounter(J0);
//        vector<ByteVector> C = GCTR(J0, P);
//        ByteVector newC = flatten(C);
//        newC.pop_back();
//        int sizeOfCinBits = newC.size()*8;
//        int sizeofAADinBits = AAD.size()*8;
//
//
//        int u = (128*ceil((double) sizeOfCinBits/128)) - sizeOfCinBits;
//        int v = (128*ceil((double) sizeofAADinBits/128)) - sizeofAADinBits;
//
//
//        ByteVector S = GHASH(padC(newC,u,v, sizeOfCinBits,sizeofAADinBits ), H);
//        prepareCounter(J0, this->IV);
//        vector<ByteVector> T = GCTR(J0,S);
//        ByteVector newT = flatten(T);
//
//
//
//        return { newC, newT };
//    }
//
//
//};
//
//int main(){
//    omp_set_num_threads(4);
//    // Key (16 bytes)
//    ByteVector Key = {
//            0x4C, 0x97, 0x3D, 0xBC, 0x73, 0x64, 0x62, 0x16,
//            0x74, 0xF8, 0xB5, 0xB8, 0x9E, 0x5C, 0x15, 0x51,
//            0x1F, 0xCE, 0xD9, 0x21, 0x64, 0x90, 0xFB, 0x1C,
//            0x1A, 0x2C, 0xAA, 0x0F, 0xFE, 0x04, 0x07, 0xE5
//    };
//    // P (Plaintext, 64 bytes)
//    ByteVector P = {};
//
//    for(int i =0;i<10;i++){
//        P.push_back(0x00);
//    }
//
//    // IV (Initialization Vector, 12 bytes)
//    ByteVector IV = {
//            0x7A, 0xE8, 0xE2, 0xCA, 0x4E, 0xC5, 0x00, 0x01,
//            0x2E, 0x58, 0x49, 0x5C
//    };
//
//    // A (Associated Data, 20 bytes)
//    ByteVector A = {
//            0x68, 0xF2, 0xE7, 0x76, 0x96, 0xCE, 0x7A, 0xE8,
//            0xE2, 0xCA, 0x4E, 0xC5, 0x88, 0xE5, 0x4D, 0x00,
//            0x2E, 0x58, 0x49, 0x5C
//    };
//
//    auto start_time = std::chrono::high_resolution_clock::now();
//
//    GCM_OpenMP gcm;
//    pair<ByteVector, ByteVector> res = gcm.encrypt(Key, IV, A,P);
//    auto end_time = std::chrono::high_resolution_clock::now();
//
//    cout << "Cipher Text: " + bytesToHex(res.first) << "\n";
//    cout << "Added Tag: " + bytesToHex(res.second) << "\n";
//    std::chrono::duration<double> elapsed_time = end_time - start_time;
//
//    // Print result
//    std::cout << "Elapsed Time: " << elapsed_time.count() << " seconds" << std::endl;
//    return 0;
//}
