#include <iostream>
#include <vector>
#include <cmath>
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
    vector<unsigned char> AAD;                 // Additional Authenticated Data

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


    vector<vector<unsigned char>> GCTR(vector<unsigned char> ICB, vector<unsigned char> val){
        AES aes;
        int n = ceil((val.size()*8)/128);
        vector<unsigned char> CB = ICB;
        vector<vector<unsigned char>> X = preparePlainText(val);
        vector<vector<unsigned char>> res;

        res.push_back(aes.encrypt(ICB, key));
        for(int i = 1;i<n;++i){
            vector<unsigned char> Y;
            incrementCounter(CB); //CBi
            Y = XorFunction(aes.encrypt(CB,key), X[i]);
            res.push_back(Y);
        }

        return res;

    }

    vector<unsigned char> GHASH(vector<unsigned char> val, vector<unsigned char> H){
        vector<unsigned char> Y0 = vector<unsigned char>(16, 0x00);
        vector<vector<unsigned char>> X = preparePlainText(val);
        for(int i = 0;i<X.size();++i){
            Y0 = gf128_multiply(XorFunction(Y0,X[i]), H);
        }
        return Y0;
    }

    vector<unsigned char> padC(vector<unsigned char> C, int u, int v, int sizeOfC, int sizeOfA) {
        vector<unsigned char> res;

       

        // Step 1: Add A to the result
        res.insert(res.end(), AAD.begin(), AAD.end());

        // Step 2: Add 0^v (v/8 bytes for A padding)
        if (v % 8 != 0) {
            throw std::invalid_argument("Padding v must be a multiple of 8.");
        }
        int paddingVBytes = v / 8;
        res.insert(res.end(), paddingVBytes, 0x00);

        // Step 3: Add C to the result
        res.insert(res.end(), C.begin(), C.end());

        // Step 4: Add 0^u (u/8 bytes for C padding)
        if (u % 8 != 0) {
            throw std::invalid_argument("Padding u must be a multiple of 8.");
        }
        int paddingUBytes = u / 8;
        res.insert(res.end(), paddingUBytes, 0x00);

        // Step 5: Encode len(A) as a 64-bit value and append
        vector<unsigned char> lenA64 = encodeLength(sizeOfA); // Length of A in bits
        if (lenA64.size() != 8) {
            throw std::logic_error("Encoded length of A must be 8 bytes.");
        }
        res.insert(res.end(), lenA64.begin(), lenA64.end());

        // Step 6: Encode len(C) as a 64-bit value and append
        vector<unsigned char> lenC64 = encodeLength(sizeOfC);
        if (lenC64.size() != 8) {
            throw std::logic_error("Encoded length of C must be 8 bytes.");
        }
        res.insert(res.end(), lenC64.begin(), lenC64.end());

        return res;
    }

    vector<unsigned char> encodeLength(uint64_t len) {
        vector<unsigned char> encoded(8, 0);
        for (int i = 7; i >= 0; --i) {
            encoded[i] = len & 0xFF;
            len >>= 8;
        }
        return encoded;
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


    vector<unsigned char> linearize(const vector<vector<unsigned char>>& C) {
        vector<unsigned char> result;

        // Loop through each vector in the 2D vector
        for (const auto& innerVector : C) {
            // Append all elements of the inner vector to the result
            result.insert(result.end(), innerVector.begin(), innerVector.end());
        }

        return result;
    }

public:
    GCM(const vector<unsigned char> key,  const vector<unsigned char> IV, const vector<unsigned char> AAD)
        : key(key), IV(IV), AAD(AAD) {}

    pair<vector<unsigned char>, vector<unsigned char>> GCM_Encrypt(vector<unsigned char> plainText) {
        AES aes;
        // Prepare H
        vector<unsigned char> H = aes.encrypt(vector<unsigned char>(16, 0x00), key);

        cout <<"H: "+ vectorToHexString(H) << endl;

        // Prepare initial counter
        vector<unsigned char> J0;
        prepareCounter(J0, IV);
        

        incrementCounter(J0); // increment J0 before start
        vector<vector<unsigned char>> C = GCTR(J0, plainText);
        vector<unsigned char> newC = linearize(C);
        int sizeOfCinBits = newC.size()*8;
        int sizeofAADinBits = AAD.size()*8;


        int u = (128*ceil(sizeOfCinBits/128)) - sizeOfCinBits;
        //int v = (128*ceil(sizeofAADinBits/128)) - sizeofAADinBits; BROOO AAM TAATENE NEGATIVE
        int v = (128 * ((sizeofAADinBits + 127) / 128)) - sizeofAADinBits;
        

        vector<unsigned char> S = GHASH(padC(newC,u,v, sizeOfCinBits,sizeofAADinBits ), H);
        

        vector<vector<unsigned char>> T = GCTR(IV,S);
        vector<unsigned char> newT = linearize(T);
        


        return { newC, newT };
    }

    std::string vectorToHexString(const std::vector<unsigned char>& byteVector) {
        std::ostringstream hexStream;

        for (unsigned char byte : byteVector) {
            hexStream << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }

        return hexStream.str();
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


    GCM gcm(Key, IV, A);
    pair<vector<unsigned char>, vector<unsigned char>> res = gcm.GCM_Encrypt(P);
    cout << "Cipher Text: "+ gcm.vectorToHexString( res.first) << "\n";
    cout << "Added Tag: "+ gcm.vectorToHexString( res.second) << "\n";

    return 0;
}
