//
// Created by ahmad on 12/1/2024.
//
#include <vector>
#include <algorithm>
#include "SubBytes.cpp"
#include <iostream>
using namespace std;

constexpr int WORDCOUNT = 60;

class KeyExpansion{
private:
    vector<unsigned char> RCON = {
            0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
            0x6C, 0xD8, 0xAB, 0x4D, 0x9A
    };
    vector<unsigned char> XorFunction(vector<unsigned char>& A, vector<unsigned char>& B){
        vector<unsigned char> C(4);
        C[0] = A[0]^B[0];
        C[1] = A[1]^B[1];
        C[2] = A[2]^B[2];
        C[3] = A[3]^B[3];
        return C;
    }
public:
    void run(vector<unsigned char> key,vector<vector<unsigned char>>& ExpandedKey){
        SubBytes subBytes;
        for (int i = 0; i < 8; ++i) {
            vector<unsigned char> word;
            for (int j = 0; j < 4; ++j) {
                word.push_back(key[i*4 + j]);
            }
            ExpandedKey[i] = word;
        }


        for (int i = 8; i < WORDCOUNT; ++i) {
            vector<unsigned char> temp = ExpandedKey[i - 1];

            if (i % 8 == 0) {

                std::rotate(temp.begin(), temp.begin() + 1, temp.end());

                subBytes.runForWord(temp);

                // XOR with RCON
                temp[0] ^= RCON[(i / 8)-1];
            } else if (i % 8 == 4) {
                // Apply SubBytes
                subBytes.runForWord(temp);
            }

            // XOR with word 8 positions back
            ExpandedKey[i] = XorFunction(temp, ExpandedKey[i - 8]);
        }
    }


};