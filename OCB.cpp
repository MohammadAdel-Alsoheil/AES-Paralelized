//
// Created by 96176 on 12/7/2024.
//


#include <iostream>
#include <vector>
#include <cmath>
#include <chrono>
#include <string>
#include <stdexcept>
#include <bitset>
#include "AES.cpp"
#include "Ghash.h"
using namespace Utils;


class OCB {
private:
    ByteVector key; // 256 bits
    ByteVector Nonce; //128 bits
    vector<ByteVector> greyCodes;

    int ntz(int value) {
        if (value == 0) return sizeof(int) * 8; // Special case: All bits are zero
        int count = 0;

        while ((value & 1) == 0) {
            count++;
            value >>= 1;
        }

        return count;
    }

    ByteVector multGreyCode(ByteVector gamma, ByteVector L, int i) {
        ByteVector result;
        for (int j = 0; j < gamma.size(); j++) {
            if (i == j) {
                result.push_back(gamma[i] ^ L[i]);
            } else {
                result.push_back(gamma[j]);
            }
        }
        return result;
    }

    ByteVector multByInverseX(const ByteVector &A) {
        ByteVector Xinverse = {
            0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x43
        };

        if (Ghash::getBit(A, A.size() - 1) == 0) {
            return Ghash::bitwiseRightShift(A);
        }
        Ghash::bitwiseRightShift(A);
        return xorF(A, Xinverse);
    }

    ByteVector encodeLength(uint64_t len) {
        ByteVector encoded(8, 0);
        for (int i = 7; i >= 0; --i) {
            encoded[i] = len & 0xFF;
            len >>= 8;
        }
        return encoded;
    }

    vector<ByteVector> DivideBlocks(ByteVector M, int blockSizeInBytes) {
        vector<ByteVector> blocks;

        // Iterate over the input ByteVector M in chunks of blockSizeInBytes
        for (size_t i = 0; i < M.size(); i += blockSizeInBytes) {
            // Get the start and end of the current block
            auto start = M.begin() + i;
            auto end = (i + blockSizeInBytes < M.size()) ? start + blockSizeInBytes : M.end();

            // Create a block and add it to the blocks list
            blocks.emplace_back(ByteVector(start, end));
        }

        return blocks;
    }

public:
    pair<ByteVector, ByteVector> encrypt(ByteVector key, ByteVector Nonce, ByteVector M) {
        if (Nonce.size() != 16) {
            throw std::invalid_argument("Nonce.size() != 16");
        }
        this->Nonce = Nonce;
        this->key = key;
        vector<ByteVector> preparedM = DivideBlocks(M, 16);
        int m = (M.size() + 15) / 16;

        //prepare L and R
        AES aes;
        ByteVector L = aes.encrypt(vector<unsigned char>(0x00, 16), key);
        ByteVector R = aes.encrypt(xorF(Nonce, L), key);


        vector<ByteVector> C; // cipherText
        vector<ByteVector> Z;
        greyCodes.push_back(L);
        Z.push_back(xorF(greyCodes[0], R));
        for (int i = 1; i < m; i++) {
            greyCodes.push_back(multGreyCode(greyCodes[i - 1], L, i));
            Z.push_back(xorF(greyCodes[i], R));
        }

        for (int i = 0; i < m - 1; i++) {
            C.push_back(xorF(aes.encrypt(xorF(preparedM[i], Z[i]), key), Z[i]));
        }

        ByteVector Xm = xorF(xorF(encodeLength(preparedM[m - 1].size() * 8), multByInverseX(L)), Z[m - 1]);
        const ByteVector Ym = aes.encrypt(Xm, key);
        ByteVector Cm; // Final ciphertext block
        for (int i = 0; i < preparedM[m - 1].size(); i++) {
            Cm.push_back(preparedM[m - 1][i] ^ Ym[i]);
        }

        C.push_back(Cm);

        // Compute the Checksum
        ByteVector Checksum(16, 0x00);
        for (int i = 0; i < m; i++) {
            Checksum = xorF(Checksum, preparedM[i]);
        }
        Checksum = xorF(xorF(Checksum, Cm), Ym);

        // Generate the authentication tag
        ByteVector T = aes.encrypt(xorF(Checksum, Z[m - 1]), key);
        T.resize(16); // Truncate to the desired tag length

        // Concatenate ciphertext blocks
        ByteVector cipherText;
        for (auto &block: C) {
            cipherText.insert(cipherText.end(), block.begin(), block.end());
        }

        // Return the ciphertext and authentication tag as a pair
        return {cipherText, T};
    }

    ByteVector decrypt(ByteVector key, ByteVector Nonce, ByteVector C, ByteVector T) {
        if (Nonce.size() != 16) {
            throw std::invalid_argument("Nonce.size() != 16");
        }
        this->Nonce = Nonce;
        this->key = key;
        greyCodes.clear();

        vector<ByteVector> preparedC = DivideBlocks(C, 16);
        int m = (C.size() + 15) / 16;

        AES aes(key);
        ByteVector L = aes.encrypt(vector<unsigned char>(0x00, 16));
        ByteVector R = aes.encrypt(xorF(Nonce, L));

        vector<ByteVector> M; // cipherText
        vector<ByteVector> Z;
        greyCodes.push_back(L);
        Z.push_back(xorF(greyCodes[0], R));
        for (int i = 1; i < m; i++) {
            greyCodes.push_back(multGreyCode(greyCodes[i - 1], L, i));
            Z.push_back(xorF(greyCodes[i], R));
        }

        for (int i = 0; i < m - 1; i++) {
            M.push_back(xorF(aes.decrypt(xorF(preparedC[i], Z[i]), key), Z[i]));
        }

        ByteVector Xm = xorF(xorF(encodeLength(preparedC[m - 1].size() * 8), multByInverseX(L)), Z[m - 1]);
        ByteVector Ym = aes.encrypt(Xm);
        ByteVector Mm;
        for (int i = 0; i < preparedC[m - 1].size(); i++) {
            Mm.push_back(preparedC[m - 1][i] ^ Ym[i]);
        }
        M.push_back(Mm);

        ByteVector Checksum(16, 0x00);
        for (int i = 0; i < m; i++) {
            Checksum = xorF(Checksum, M[i]);
        }
        Checksum = xorF(xorF(Checksum, preparedC[m - 1]), Ym);
        // Generate the authentication tag
        ByteVector Tprime = aes.encrypt(xorF(Checksum, Z[m - 1]));
        Tprime.resize(16); // Truncate to the desired tag length

        // Concatenate ciphertext blocks
        for (int i = 0; i < 16; i++) {
            if (T[i] != Tprime[i]) {
                throw std::invalid_argument("No integrity between messages");
            }
        }

        return flatten(M);
    }
};

// 08000f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748490008
// 08000f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c47516637c11adefb4194d54e0ae7fa
// 009391b1249a57519eb8efbd91884aee40a4eba4d2d8b88f661f872f9c3dfd656097476fa8e4697572a3df97c52c5f0279310758893200d4f0023b0175b587

int main() {
    OCB ocb;

    // Key (32 bytes)
    ByteVector Key = {
        0x4C, 0x97, 0x3D, 0xBC, 0x73, 0x64, 0x62, 0x16,
        0x74, 0xF8, 0xB5, 0xB8, 0x9E, 0x5C, 0x15, 0x51,
        0x1F, 0xCE, 0xD9, 0x21, 0x64, 0x90, 0xFB, 0x1C,
        0x1A, 0x2C, 0xAA, 0x0F, 0xFE, 0x04, 0x07, 0xE5
    };
    // P (Plaintext, 64 bytes)
    ByteVector P;
    for (int i = 0; i < 100000000; i++) {
        P.push_back(0x00);
    }
    // ByteVector P = {
    //     0x08, 0x00, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14,
    //     0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
    //     0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24,
    //     0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C,
    //     0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34,
    //     0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C,
    //     0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44,
    //     0x45, 0x46, 0x47, 0x48, 0x49, 0x00, 0x08
    // };

    // IV (Initialization Vector, 16 bytes)
    ByteVector Nonce = {
        0x7A, 0xE8, 0xE2, 0xCA, 0x4E, 0xC5, 0x00, 0x01,
        0x2E, 0x58, 0x49, 0x5C, 0x2E, 0x58, 0x49, 0x5C
    };

    //cout << "P: " << Utils::bytesToHex(P) << endl;
    auto startEnc = chrono::high_resolution_clock::now();
    pair<ByteVector, ByteVector> cipher = ocb.encrypt(Key, Nonce, P);
    auto endEnc = chrono::high_resolution_clock::now();
    auto durationEnc = chrono::duration_cast<chrono::microseconds>(endEnc - startEnc).count();
    //cout << "Cipher Text is: " << Utils::bytesToHex(cipher.first) << endl;
    //cout << "Tag is: " << Utils::bytesToHex(cipher.second) << endl;
    auto startDec = chrono::high_resolution_clock::now();
    ByteVector M = ocb.decrypt(Key, Nonce, cipher.first, cipher.second);
    auto endDec = chrono::high_resolution_clock::now();
    auto durationDec = chrono::duration_cast<chrono::microseconds>(endDec - startDec).count();
    //cout << "Deciphered Text is: " << Utils::bytesToHex(M) << endl;
    std::cout << "Encryption of a " + std::to_string(P.size()) + " bytes took "
            + std::to_string((double)durationEnc/1000000) + " seconds" << std::endl;
    std::cout << "Decryption of a " + std::to_string(cipher.first.size()) + " bytes took "
            + std::to_string((double)durationDec/1000000) + " seconds" << std::endl;


    return 0;
}

