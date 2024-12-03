#include <iostream>
#include <vector>
#include <string>
#include <sstream>    // For std::ostringstream
#include <iomanip>    // For std::hex, std::setw, std::setfill
#include <stdexcept>  // For std::invalid_argument
#include "AES.cpp"    // Ensure this file is included and implements the AES class

using namespace std;

class GCM {
private:
    vector<unsigned char> key;                 // 256-bit key
    vector<unsigned char> IV;                  // Recommended to be 96 bits
    vector<vector<unsigned char>> states;      // Plaintext blocks
    vector<unsigned char> AAD;                 // Additional Authenticated Data
    size_t tagLength;

    // Function to prepare the initial counter based on the IV
    void prepareCounter(vector<unsigned char>& counter, const vector<unsigned char>& IV) {
        if (IV.size() == 12) {
            // If IV is 96 bits, append 0x00000001 to form J0
            counter = IV;
            counter.push_back(0x00);
            counter.push_back(0x00);
            counter.push_back(0x00);
            counter.push_back(0x01);
        } else {
            throw invalid_argument("IV must be 96 bits (12 bytes) in this implementation.");
        }
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

    vector<vector<unsigned char>> preparePlainText(const vector<unsigned char>& plainTextBytes) {
        vector<vector<unsigned char>> blocks;
        for (size_t i = 0; i < plainTextBytes.size(); i += 16) {
            vector<unsigned char> block(16, 0x00);
            for (size_t j = 0; j < 16 && (i + j) < plainTextBytes.size(); ++j) {
                block[j] = plainTextBytes[i + j];
            }
            
            // Add the block to the blocks vector
            blocks.push_back(block);
        }

        return blocks;
    }


    vector<unsigned char> gf128_multiply(const vector<unsigned char>& X, const vector<unsigned char>& H) {
        if (X.size() != 16 || H.size() != 16) {
            throw std::invalid_argument("X and H must be 16 bytes long.");
        }

        vector<unsigned char> result(16, 0x00);
        vector<unsigned char> V = H;

        for (int i = 0; i < 128; ++i) {
            if ((X[i / 8] >> (7 - (i % 8))) & 1) {
                for (int j = 0; j < 16; ++j) {
                    result[j] ^= V[j];
                }
            }

            bool carry = V[0] & 0x80;
            for (int j = 0; j < 15; ++j) {
                V[j] = (V[j] << 1) | (V[j + 1] >> 7);
            }
            V[15] <<= 1;

            if (carry) {
                V[15] ^= 0x87;
            }
        }

        return result;
    }

    std::vector<unsigned char> hexStringToVector(const std::string& hexString) {
        if (hexString.length() % 2 != 0) {
            throw std::invalid_argument("Hex string must have an even length.");
        }

        std::vector<unsigned char> byteVector;

        for (size_t i = 0; i < hexString.length(); i += 2) {
            std::string hexByte = hexString.substr(i, 2);

            unsigned char byte = static_cast<unsigned char>(std::stoi(hexByte, nullptr, 16));
            byteVector.push_back(byte);
        }

        return byteVector;
    }

    std::string vectorToHexString(const std::vector<unsigned char>& byteVector) {
        std::ostringstream hexStream;

        for (unsigned char byte : byteVector) {
            hexStream << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }

        return hexStream.str();
    }

public:
    GCM(const string& plainTextHex, const string& keyHex, const string& IVHex,
        const string& AADHex, size_t tagLength)
            : key(hexStringToVector(keyHex)), IV(hexStringToVector(IVHex)),
              AAD(hexStringToVector(AADHex)), tagLength(tagLength) {

        vector<unsigned char> plaintextBytes = hexStringToVector(plainTextHex);
        states = preparePlainText(plaintextBytes);
    }

    pair<string, string> GCM_Encrypt() {
        AES aes;
        string cipherText;

        // Prepare H
        vector<unsigned char> H = aes.encrypt(vector<unsigned char>(16, 0x00), key);

        cout << vectorToHexString(H) << endl;
        // Prepare initial counter
        vector<unsigned char> counter;
        prepareCounter(counter, IV);

        vector<unsigned char> ciphertextRaw; // Raw binary ciphertext storage
        vector<unsigned char> counterZeroEncrypted = aes.encrypt(counter, key);

        vector<unsigned char> paddedAAD = AAD; // Start with the given AAD
        if (paddedAAD.size() % 16 != 0) {
            paddedAAD.resize(((paddedAAD.size() + 15) / 16) * 16, 0x00);
        }
        vector<unsigned char> authTag= gf128_multiply(H,paddedAAD);

        for (const auto& block : states) {
            incrementCounter(counter);
            vector<unsigned char> encCounter = aes.encrypt(counter, key);
            vector<unsigned char> C = XorFunction(encCounter, block);
            ciphertextRaw.insert(ciphertextRaw.end(), C.begin(), C.end());
            authTag= XorFunction(authTag,C);
            authTag= gf128_multiply(H,authTag);
        }
        cipherText = vectorToHexString(ciphertextRaw); // Convert to hex string for output


        return { cipherText, vectorToHexString(authTag) };
    }
};


int main() {
    try {
        GCM gcm(
                "08000F101112131415161718191A1B1C"
                "1D1E1F202122232425262728292A2B2C"
                "2D2E2F303132333435363738393A3B3C"
                "3D3E3F404142434445464748490008"
                ,   // Plaintext in hex
                "4C973DBC7364621674F8B5B89E5C1551"
                "1FCED9216490FB1C1A2CAA0FFE0407E5"
                ,  // Key in hex
                "7AE8E2CA4EC500012E58495C",      // IV in hex
                "68F2E77696CE7AE8E2CA4EC588E54D00"
                "2E58495C",          // AAD in hex
                16                               // Tag length
        );

        pair<string, string> res = gcm.GCM_Encrypt();
        cout << "Cipher Text: " << res.first << "\n";
        cout << "Authentication Tag: " << res.second << "\n";
    } catch (const exception& e) {
        cerr << "Error: " << e.what() << endl;
    }

    return 0;
}
