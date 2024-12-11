//
// Created by ahmad on 12/4/2024.
//

#include <bitset>
#include "Ghash.h"
#include "Utils.h"
#include <immintrin.h>


namespace Ghash{
    ByteVector gf128Multiply(const ByteVector& X, const ByteVector& Y) {

        ByteVector Z0(16, 0x00);
        ByteVector V0 = Y;
        ByteVector R =  {0xe1,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

        for (int i = 0; i < 128; ++i) {
            if (getBit(X,i) == 1) {
                Z0 = Utils::xorF(Z0, V0);
            }
            bool lsb = getBit(V0, 127); //last bit
            V0 = bitwiseRightShift(V0);
            if (lsb == 1) {
                V0 = Utils::xorF(V0,R);
            }
        }

        return Z0;
    }
    bool getBit(const ByteVector& vec, int bitIndex) {
        int byteIndex = bitIndex / 8;
        int bitPosition = 7 - (bitIndex % 8);

        return (vec[byteIndex] >> bitPosition) & 1;
    }
    ByteVector bitwiseRightShift(ByteVector vec) {
        string bits = "0";
        int n = vec.size() * 8; // Total number of bits

        for (int i = 0; i < n-1; ++i) {
            bits = bits + to_string(getBit(vec, i));
        }
        ByteVector byteVector;
        for (size_t i = 0; i < bits.length(); i += 8) {
            // Take 8 bits at a time, convert to unsigned char
            bitset<8> byte(bits.substr(i, 8));  // Convert substring of 8 bits to std::bitset
            byteVector.push_back(static_cast<unsigned char>(byte.to_ulong()));  // Convert to unsigned char
        }

        return byteVector;
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
}