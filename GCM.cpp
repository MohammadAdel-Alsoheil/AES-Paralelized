#include <iostream>
#include <vector>
#include <string>
#include <cstdint>
#include "AES.cpp" // Ensure this file is included and implements the AES class

using namespace std;

class GCM {
private:
    vector<unsigned char> key;                 // 256-bit key
    vector<unsigned char> IV;                  // Recommended to be 96 bits
    vector<vector<unsigned char>> states;      // Plaintext blocks
    vector<unsigned char> AAD;                 // Additional Authenticated Data
    size_t tagLength;

    void padIV(vector<unsigned char>& IV) {
        for (int i = 0; i < 31; ++i) {
            IV.push_back(0x00);
        }
        IV.push_back(0x01);
    }

    vector<unsigned char> XorFunction(const vector<unsigned char>& A, const vector<unsigned char>& B) {
        vector<unsigned char> C(A.size());
        for (size_t i = 0; i < A.size(); ++i) {
            C[i] = A[i] ^ B[i];
        }
        return C;
    }

    void incrementCounter(vector<unsigned char>& counter) {
        for (int i = 15; i >= 12; --i) { // Last 4 bytes represent the counter
            if (++counter[i] != 0) {
                break; // Stop incrementing if no overflow
            }
        }
    }

    vector<vector<unsigned char>> preparePlainText(const vector<unsigned char>& plainText) {
        vector<vector<unsigned char>> blocks;

        for (size_t i = 0; i < plainText.size(); i += 16) {
            // Create a block of 16 bytes initialized to 0x00 (for padding)
            vector<unsigned char> block(16, 0x00);
            
            // Copy up to 16 bytes from the plaintext into the block
            for (size_t j = 0; j < 16 && (i + j) < plainText.size(); ++j) {
                block[j] = plainText[i + j];
            }
            
            // Add the block to the blocks vector
            blocks.push_back(block);
        }

        return blocks;
    }


    vector<unsigned char> ghash(const vector<unsigned char>& H, const vector<unsigned char>& data) {
        vector<unsigned char> X(16, 0x00);
        for (size_t i = 0; i < data.size(); i += 16) {
            vector<unsigned char> block(data.begin() + i, data.begin() + min(i + 16, data.size()));
            block.resize(16, 0x00);
            X = XorFunction(X, block);
            X = gf128_multiply(X, H);
        }
        return X;
    }

    vector<unsigned char> gf128_multiply(const vector<unsigned char>& X, const vector<unsigned char>& H) {
        vector<unsigned char> result(16, 0x00);
        vector<unsigned char> V = H;

        for (int i = 0; i < 128; ++i) {
            if ((X[i / 8] >> (7 - (i % 8))) & 1) {
                for (int j = 0; j < 16; ++j) {
                    result[j] ^= V[j];
                }
            }

            bool carry = V[15] & 1;
            for (int j = 15; j > 0; --j) {
                V[j] = (V[j] >> 1) | ((V[j - 1] & 1) << 7);
            }
            V[0] >>= 1;

            if (carry) {
                V[0] ^= 0xe1;
            }
        }

        return result;
    }

    std::vector<unsigned char> hexStringToVector(const std::string& hexString) {
        std::vector<unsigned char> byteVector;

        // Iterate over the string in pairs of characters
        for (size_t i = 0; i < hexString.length(); i += 2) {
            // Extract a pair of characters
            std::string hexByte = hexString.substr(i, 2);

            // Convert the hex pair to an unsigned char and add to the vector
            unsigned char byte = static_cast<unsigned char>(std::stoi(hexByte, nullptr, 16));
            byteVector.push_back(byte);
        }

        return byteVector;
    }
       std::string vectorToHexString(const std::vector<unsigned char>& byteVector) {
            std::ostringstream hexStream;

            for (unsigned char byte : byteVector) {
                // Convert each byte to a 2-character hex string and append it to the stream
                hexStream << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
            }

            return hexStream.str(); // Return the constructed hex string
        }

public:
    GCM(const vector<unsigned char> plainText, const vector<unsigned char> key,  const vector<unsigned char> IV, const vector<unsigned char> AAD, size_t tagLength)
        : key(key), IV(IV), AAD(AAD), tagLength(tagLength) {
        states = preparePlainText(plainText);
    }

    pair<string, string> GCM_Encrypt() {
        AES aes;
        string cipherText;

        // Prepare H
        vector<unsigned char> H = aes.encrypt(vector<unsigned char>(16, 0x00), key);

        // Pad IV and prepare initial counter
        vector<unsigned char> counter = IV;
        padIV(counter);

        for (const auto& block : states) {
            incrementCounter(counter);
            vector<unsigned char> encCounter = aes.encrypt(counter, key);
            vector<unsigned char> C = XorFunction(encCounter, block);
            cipherText += vectorToHexString(C);
        }

        // Prepare GHASH input
        vector<unsigned char> GHASH_input;
        GHASH_input.insert(GHASH_input.end(), AAD.begin(), AAD.end());
        GHASH_input.insert(GHASH_input.end(), cipherText.begin(), cipherText.end());
        GHASH_input.push_back(AAD.size() * 8);         // Append bit length of AAD
        GHASH_input.push_back(states.size() * 128);    // Append bit length of plaintext
        vector<unsigned char> S = ghash(H, GHASH_input);

        // Compute the final authentication tag
        vector<unsigned char> T = XorFunction(aes.encrypt(counter, key), S);
        T.resize(tagLength);

        return {cipherText, vectorToHexString(T)};
    }
};

int main(){
    // Key (16 bytes)
    vector<unsigned char> Key = {
        0x4C, 0x97, 0x3D, 0xBC, 0x73, 0x64, 0x62, 0x16, 
        0x74, 0xF8, 0xB5, 0xB8, 0x9B, 0x5C, 0x15, 0x51
    };

    // P (Plaintext, 64 bytes)
    vector<unsigned char> P = {
        0x1F, 0xCE, 0xD9, 0x21, 0x64, 0x90, 0xFB, 0x1C,
        0x1A, 0x2C, 0xAA, 0x0F, 0xFE, 0x04, 0x07, 0xE5,
        0x08, 0x00, 0x01, 0x01, 0x11, 0x21, 0x31, 0x41,
        0x51, 0x61, 0x71, 0x81, 0x91, 0xA1, 0xB1, 0xC1,
        0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24,
        0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C,
        0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34,
        0x35, 0x36, 0x37, 0x38, 0x39, 0x33, 0xB3, 0xC3,
        0x3D, 0x33, 0xF4, 0x04, 0x14, 0x24, 0x34, 0x44,
        0x45, 0x46, 0x47, 0x48, 0x49, 0x00, 0x08
    };

    // IV (Initialization Vector, 12 bytes)
    vector<unsigned char> IV = {
        0x7A, 0xE8, 0xE2, 0xCA, 0x4E, 0xC5, 0x00, 0x01, 
        0x2E, 0x58, 0x49, 0x5C
    };

    // A (Associated Data, 28 bytes)
    vector<unsigned char> A = {
        0x68, 0xF2, 0xE7, 0x76, 0x96, 0xC7, 0xAE, 0x8E,
        0x2C, 0xA4, 0xEC, 0x58, 0x8B, 0x54, 0xD0, 0x00,
        0x25, 0x84, 0x95, 0xC0
    };


    GCM gcm(P, Key, IV, A, 28);
    pair<string, string> res = gcm.GCM_Encrypt();
    cout << "Cipher Text: "+res.first << "\n";
    cout << "Added Tag: "+ res.second << "\n";

    return 0;
}

