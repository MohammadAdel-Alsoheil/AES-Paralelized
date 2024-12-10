//
// Created by ahmad on 12/4/2024.
//

#include <bitset>
#include "Ghash.h"
#include "Utils.h"


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
}