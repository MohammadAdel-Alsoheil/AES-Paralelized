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

    vector<vector<unsigned char>> preparePlainText(const string& plainText) {
        vector<vector<unsigned char>> blocks;
        for (size_t i = 0; i < plainText.size(); i += 16) {
            vector<unsigned char> block(16, 0x00);
            for (size_t j = 0; j < 16 && (i + j) < plainText.size(); ++j) {
                block[j] = plainText[i + j];
            }
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
    GCM(const string& plainText, const string& key,  const string& IV,
        const string&& AAD, size_t tagLength)
        : key(hexStringToVector(key)), IV(hexStringToVector(IV)), AAD(hexStringToVector(AAD)), tagLength(tagLength) {
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
    GCM gcm("hellotherehellotherehellothereAhmadAhmadAhmadAhmad","000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f","ba7313be2caadbe1469bea4a9a","a00f37eab080a3032e4882cf1f558134",16);
    pair<string, string> res = gcm.GCM_Encrypt();
    cout << "Cipher Text: "+res.first << "\n";
    cout << "Added Tag: "+ res.second << "\n";

    return 0;
}