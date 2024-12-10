#include <iostream>
#include <vector>
#include <cmath>
#include <string>
#include <stdexcept>
#include "AES.cpp"
#include "Ghash.h"
#include <chrono>
#include <immintrin.h>

using namespace Utils;


class GCM {
private:
    ByteVector key;
    ByteVector IV;
    ByteVector AAD;
    vector<ByteVector> gf128Res;

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


    vector<ByteVector> GCTR(ByteVector ICB, ByteVector val){
        AES aes(key);
        ByteVector CB = ICB;
        vector<ByteVector> X = nest(val,16);
        vector<ByteVector> res;
        for(int i = 0;i<X.size();++i){
            ByteVector Y;
            Y = xorF(aes.encrypt(CB), X[i]);
            incrementCounter(CB);
            res.push_back(Y);
        }

        return res;
    }
    void clmul_x86(uint8_t r[16], const uint8_t a[16], const uint8_t b[16])
    {
        const __m128i MASK = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);

        __m128i a1 = _mm_loadu_si128((const __m128i*)a);
        __m128i b1 = _mm_loadu_si128((const __m128i*)b);

        a1 = _mm_shuffle_epi8(a1, MASK);
        b1 = _mm_shuffle_epi8(b1, MASK);

        __m128i T0, T1, T2, T3, T4, T5;

        T0 = _mm_clmulepi64_si128(a1, b1, 0x00);
        T1 = _mm_clmulepi64_si128(a1, b1, 0x01);
        T2 = _mm_clmulepi64_si128(a1, b1, 0x10);
        T3 = _mm_clmulepi64_si128(a1, b1, 0x11);

        T1 = _mm_xor_si128(T1, T2);
        T2 = _mm_slli_si128(T1, 8);
        T1 = _mm_srli_si128(T1, 8);
        T0 = _mm_xor_si128(T0, T2);
        T3 = _mm_xor_si128(T3, T1);

        T4 = _mm_srli_epi32(T0, 31);
        T0 = _mm_slli_epi32(T0, 1);

        T5 = _mm_srli_epi32(T3, 31);
        T3 = _mm_slli_epi32(T3, 1);

        T2 = _mm_srli_si128(T4, 12);
        T5 = _mm_slli_si128(T5, 4);
        T4 = _mm_slli_si128(T4, 4);
        T0 = _mm_or_si128(T0, T4);
        T3 = _mm_or_si128(T3, T5);
        T3 = _mm_or_si128(T3, T2);

        T4 = _mm_slli_epi32(T0, 31);
        T5 = _mm_slli_epi32(T0, 30);
        T2 = _mm_slli_epi32(T0, 25);

        T4 = _mm_xor_si128(T4, T5);
        T4 = _mm_xor_si128(T4, T2);
        T5 = _mm_srli_si128(T4, 4);
        T3 = _mm_xor_si128(T3, T5);
        T4 = _mm_slli_si128(T4, 12);
        T0 = _mm_xor_si128(T0, T4);
        T3 = _mm_xor_si128(T3, T0);

        T4 = _mm_srli_epi32(T0, 1);
        T1 = _mm_srli_epi32(T0, 2);
        T2 = _mm_srli_epi32(T0, 7);
        T3 = _mm_xor_si128(T3, T1);
        T3 = _mm_xor_si128(T3, T2);
        T3 = _mm_xor_si128(T3, T4);

        T3 = _mm_shuffle_epi8(T3, MASK);

        _mm_storeu_si128((__m128i*)r, T3);
    }
    ByteVector gf128Multiply(const ByteVector &X, const ByteVector &H) {
        if (X.size() != 16 || H.size() != 16) {
            throw std::runtime_error("gf128Multiply: Input vectors must be 16 bytes.");
        }

        ByteVector result(16);
        clmul_x86(result.data(), X.data(), H.data());
        return result;
    }


    void computeGF128Power(const ByteVector &H, int size, std::vector<ByteVector> &gf128Res) {
        gf128Res.resize(size);
        gf128Res[0] = H;
        ByteVector current = H;
        for (int i = 1; i < size; ++i) {
            current = gf128Multiply(current, H);
            gf128Res[i] = current;
        }
    }

    ByteVector GHASH(const ByteVector &X, const ByteVector &H) {
        // nest into 16-byte blocks
        auto nest = [](const ByteVector &data, size_t blockSize) {
            std::vector<ByteVector> blocks;
            for (size_t i = 0; i < data.size(); i += blockSize) {
                ByteVector block(16, 0);
                size_t len = std::min(blockSize, data.size() - i);
                for (size_t j = 0; j < len; j++) {
                    block[j] = data[i + j];
                }
                blocks.push_back(block);
            }
            return blocks;
        };

        // XOR helper
        auto xorF = [](const ByteVector &a, const ByteVector &b) {
            ByteVector res(16);
            for (int i = 0; i < 16; ++i) {
                res[i] = a[i] ^ b[i];
            }
            return res;
        };

        std::vector<ByteVector> blocks = nest(X, 16);
        int numBlocks = (int)blocks.size();

        std::vector<ByteVector> gf128Res;
        computeGF128Power(H, numBlocks, gf128Res);

        ByteVector tag(16, 0x00);

        for (int i = 0; i < numBlocks; ++i) {
            ByteVector hPower = gf128Res[numBlocks - i - 1];
            ByteVector term = gf128Multiply(blocks[i], hPower);
            tag = xorF(tag, term);
        }

        return tag;
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
    pair<ByteVector, ByteVector> encrypt(const ByteVector key, const ByteVector IV, const ByteVector AAD,
                                         ByteVector P) {
        this->AAD = AAD;
        this->IV = IV;
        this->key = key;

        AES aes(key);
        int sizeOfPlainText = P.size();
        ByteVector H = aes.encrypt(ByteVector(16, 0x00));


        ByteVector J0;
        prepareCounter(J0, this->IV);


        incrementCounter(J0);
        vector<ByteVector> C = GCTR(J0, P);
        ByteVector newC = flatten(C);

        //removes padding
        while (sizeOfPlainText < newC.size()) {
            newC.pop_back();
            sizeOfPlainText++;
        }

        int sizeOfCinBits = newC.size() * 8;
        int sizeofAADinBits = AAD.size() * 8;

        int u = (128 * ceil((double) sizeOfCinBits / 128)) - sizeOfCinBits;
        int v = (128 * ceil((double) sizeofAADinBits / 128)) - sizeofAADinBits;

        ByteVector S = GHASH(padC(newC, u, v, sizeOfCinBits, sizeofAADinBits), H);

        prepareCounter(J0, this->IV);
        vector<ByteVector> T = GCTR(J0, S);
        ByteVector newT = flatten(T);


        return {newC, newT};
    }

    ByteVector decrypt(const ByteVector key, const ByteVector IV, const ByteVector AAD, ByteVector C, ByteVector T) {
        // outputs plainText
        this->AAD = AAD;
        this->IV = IV;
        this->key = key;

        AES aes(key);
        int sizeOfCipherText = C.size();
        ByteVector H = aes.encrypt(ByteVector(16, 0x00));


        ByteVector J0;
        prepareCounter(J0, this->IV);


        incrementCounter(J0);
        vector<ByteVector> P = GCTR(J0, C);
        ByteVector newP = flatten(P);

        //removes padding
        while (sizeOfCipherText < newP.size()) {
            newP.pop_back();
            sizeOfCipherText++;
        }

        int sizeOfCinBits = C.size() * 8;
        int sizeofAADinBits = AAD.size() * 8;

        int u = (128 * ceil((double) sizeOfCinBits / 128)) - sizeOfCinBits;
        int v = (128 * ceil((double) sizeofAADinBits / 128)) - sizeofAADinBits;

        ByteVector S = GHASH(padC(C, u, v, sizeOfCinBits, sizeofAADinBits), H);

        prepareCounter(J0, this->IV);
        vector<ByteVector> Tprime = GCTR(J0, S);
        ByteVector newTprime = flatten(Tprime);

        for (int i = 0; i < 16; ++i) {
            if (T[i] != newTprime[i]) {
                throw invalid_argument("There is no integrity between T and Tprime");
            }
        }

        return newP;
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
    ByteVector P;

    for(int i =0;i<1000000;i++){
        P.push_back(0x00);
    }

    ByteVector IV = {
            0x7A, 0xE8, 0xE2, 0xCA, 0x4E, 0xC5, 0x00, 0x01,
            0x2E, 0x58, 0x49, 0x5C
    };

    ByteVector A = {
            0x68, 0xF2, 0xE7, 0x76, 0x96, 0xCE, 0x7A, 0xE8,
            0xE2, 0xCA, 0x4E, 0xC5, 0x88, 0xE5, 0x4D, 0x00,
            0x2E, 0x58, 0x49, 0x5C
    };

    auto start_time = std::chrono::high_resolution_clock::now();

    GCM gcm;
    pair<ByteVector, ByteVector> res = gcm.encrypt(Key, IV, A,P);
    auto end_time = std::chrono::high_resolution_clock::now();

    ByteVector deciphered = gcm.decrypt(Key,IV,A,res.first,res.second);
//    cout << "Decrypted Text: " + bytesToHex(deciphered) << "\n";
//    cout << "Cipher Text: " + bytesToHex(res.first) << "\n";
    cout << "Added Tag: " + bytesToHex(res.second) << "\n";
    std::chrono::duration<double> elapsed_time = end_time - start_time;

    // Print result
    std::cout << "Elapsed Time: " << elapsed_time.count() << " seconds" << std::endl;
    return 0;
}
