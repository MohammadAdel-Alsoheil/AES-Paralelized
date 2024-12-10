#include <iostream>
#include <vector>
#include <cmath>
#include <string>
#include <stdexcept>
#include "AES.cpp"
#include "Ghash.h"
#include <chrono>

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

    void computeGF128Power(const ByteVector&H,int size){
        this->gf128Res.resize(size);
        this->gf128Res[0]=H;
        for(int i =1;i<size;i++){
            this->gf128Res[i] = Ghash::gf128Multiply(this->gf128Res[i-1],H);
        }
    }

    ByteVector GHASH(const ByteVector &val, const ByteVector &H) {
        // Break input into 16-byte blocks
        std::vector<ByteVector> X = nest(val, 16);
        int numBlocks = X.size();

        // Precompute powers of H
        this->computeGF128Power(H, numBlocks);

        // Initialize the tag (Y0 = 0)
        ByteVector tag(16, 0x00);

        // Parallel processing with OpenMP using the custom reduction
        for (int i = 0; i < numBlocks; ++i) {
            // Access precomputed power of H
            ByteVector hPower = this->gf128Res[numBlocks - i - 1]; // Correct index

            // Multiply the current block by the corresponding power of H
            ByteVector term = Ghash::gf128Multiply(X[i], hPower);

            // XOR into the reduction variable 'tag'
            tag = xorF(tag, term);
        }

        return tag; // Return the final computed tag
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

    for(int i =0;i<1000;i++){
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
    cout << "Decrypted Text: " + bytesToHex(deciphered) << "\n";
    cout << "Cipher Text: " + bytesToHex(res.first) << "\n";
    cout << "Added Tag: " + bytesToHex(res.second) << "\n";
    std::chrono::duration<double> elapsed_time = end_time - start_time;

    // Print result
    std::cout << "Elapsed Time: " << elapsed_time.count() << " seconds" << std::endl;
    return 0;
}
