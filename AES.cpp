#include <iostream>

#include <random>
#include <vector>
#include <iomanip>
#include "./aes_stages/KeyExpansion.cpp"
#include "./aes_stages/MixColumns.cpp"
#include "./aes_stages/ShiftRows.cpp"
#include "./aes_stages/InverseSubBytes.cpp"
#include "./aes_stages/InverseMixColumns.cpp"
#include "./aes_stages/InverseShiftRows.cpp"

using namespace std;

constexpr int SIZE = 4;
constexpr int KEYSIZE = 32;

class AES {
private:
    ByteVector key; // 256 bits or 32 bytes
    vector<ByteVector> ExpandedKey{60, ByteVector(4)}; // 60 words or 240 bytes
    vector<ByteVector> state{4, vector<unsigned char>(4)};

    void addRoundKey(int roundNumber) {
        //correct

        int start = roundNumber * 4; // 0 for 1st round
        for (int i = 0; i < 4; ++i) {
            for (int j = 0; j < 4; ++j) {
                state[j][i] = state[j][i] ^ ExpandedKey[start + i][j]; //changed this to (j,i)
            }
        }
    }


    void convertToStateMatrix(ByteVector bytes) {
        for (size_t i = 0; i < bytes.size(); ++i) {
            size_t col = i / 4;
            size_t row = i % 4;
            state[row][col] = bytes[i];
        }
    }

    ByteVector stateToHexVector() {
        ByteVector bytes;

        for (int i = 0; i < 4; ++i) {
            for (int j = 0; j < 4; ++j) {
                bytes.push_back(state[j][i]);
            }
        }
        return bytes;
    }

public:
    ByteVector encrypt(ByteVector plainText, ByteVector givenKey) {
        key = givenKey;
        convertToStateMatrix(plainText);
        KeyExpansion keyExpansion;
        SubBytes subBytes;
        ShiftRows shiftRows;
        MixColumns mixColumns;
        keyExpansion.run(key, ExpandedKey); // correct
        addRoundKey(0);

        for (int i = 1; i <= 14; i++) {
            subBytes.runForState(state);
            shiftRows.run(state);
            if (i != 14) {
                mixColumns.run(state);
            }
            addRoundKey(i);
        }

        return stateToHexVector();
    }

    ByteVector decrypt(ByteVector cipherText, ByteVector givenKey) {
        key = givenKey;
        convertToStateMatrix(cipherText);
        KeyExpansion keyExpansion;
        InverseSubBytes inverseSuBytes;
        InverseMixColumns inverseMixColumns;
        InverseShiftRows inverseShiftRows;
        keyExpansion.run(key, ExpandedKey);

        for (int i = 14; i >= 1; --i) {
            addRoundKey(i);
            if (i != 14) {
                inverseMixColumns.run(state);
            }
            inverseShiftRows.run(state);
            inverseSuBytes.runForState(state);
        }

        addRoundKey(0);

        return stateToHexVector();
    }
};

// int main() {
//     std::vector<unsigned char> vec = {
//         0x71, 0x69, 0xAB, 0x15, 0x33, 0x9C, 0xFB, 0xC4,
//         0x26, 0x42, 0xE4, 0xDB, 0x05, 0x94, 0xD5, 0xEE
//     };
//
//     ByteVector Key = {
//         0x4C, 0x97, 0x3D, 0xBC, 0x73, 0x64, 0x62, 0x16,
//         0x74, 0xF8, 0xB5, 0xB8, 0x9E, 0x5C, 0x15, 0x51,
//         0x1F, 0xCE, 0xD9, 0x21, 0x64, 0x90, 0xFB, 0x1C,
//         0x1A, 0x2C, 0xAA, 0x0F, 0xFE, 0x04, 0x07, 0xE5
//     };
//
//     AES aes;
//     ByteVector res = aes.encrypt(vec, Key);
//
//     cout << Utils::bytesToHex(res) << endl;
//
//     return 0;
// }
