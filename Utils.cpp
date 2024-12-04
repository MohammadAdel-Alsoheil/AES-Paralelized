//
// Created by ahmad on 12/4/2024.
//

#include "Utils.h"
#include <string>
#include <iostream>
#include <vector>
#include <sstream>
#include <iomanip>
#include "AES.cpp"
using namespace std;

namespace Utils{
    string bytesToHex(const ByteVector & byteVector) {
        ostringstream hexStream;
        for (unsigned char byte : byteVector) {
            hexStream << hex << setw(2) << setfill('0') << static_cast<int>(byte);
        }
        return hexStream.str();
    }

    ByteVector xorF(const ByteVector &A, const ByteVector &B) {
        ByteVector C(A.size());
        transform(A.begin(), A.end(), B.begin(), C.begin(), [](unsigned char a, unsigned char b) {
            return a ^ b;
        });
        return C;
    }

    vector<ByteVector> nest(const ByteVector& plainText,int size) {
        vector<ByteVector> blocks;

        for (size_t i = 0; i < plainText.size(); i += size) {
            ByteVector block(size, 0x00);

            for (size_t j = 0; j < size && (i + j) < plainText.size(); ++j) {
                block[j] = plainText[i + j];
            }
            blocks.push_back(block);
        }
        while(size==4 && blocks.size()!=4){
            blocks.push_back(ByteVector(0x00,4));
        }
        return blocks;
    }

    ByteVector flatten(const vector<ByteVector>& C) {
        ByteVector result;

        for (const auto& block : C) {
            result.insert(result.end(), block.begin(), block.end());
        }

        return result;
    }
}