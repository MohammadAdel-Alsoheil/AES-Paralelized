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

class AES{

private:
    ByteVector key; // 256 bits or 32 bytes
    vector<ByteVector> ExpandedKey{60, ByteVector(4)}; // 60 words or 240 bytes
    vector<ByteVector> state{4,vector<unsigned  char>(4)};

    void addRoundKey(int roundNumber){ //correct

        int start = roundNumber * 4; // 0 for 1st round
        for (int i = 0; i < 4; ++i) {
            for (int j = 0; j < 4; ++j) {
                state[j][i] = state[j][i] ^ ExpandedKey[start +i][j]; //changed this to (j,i)

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

        for(int i = 0;i<4;++i){
            for(int j = 0;j<4;++j){
                bytes.push_back(state[j][i]);
            }
        }
        return bytes;
    }

public:
    AES(ByteVector givenKey){
        key = givenKey;
        KeyExpansion keyExpansion;
        keyExpansion.run(key,ExpandedKey); // instead of calculating them everytime
    }

    ByteVector encrypt(ByteVector plainText){
        convertToStateMatrix(plainText);
        SubBytes subBytes;
        ShiftRows shiftRows;
        MixColumns mixColumns;
        addRoundKey(0);

        for(int i =1;i<=14;i++){
            subBytes.runForState(state);
            shiftRows.run(state);
            if(i!=14){
                mixColumns.run(state);
            }
            addRoundKey(i);

        }

        return stateToHexVector();
    }

    ByteVector decrypt(ByteVector cipherText, ByteVector givenKey){
        key = givenKey;
        convertToStateMatrix(cipherText);
        KeyExpansion keyExpansion;
        InverseSubBytes inverseSuBytes;
        InverseMixColumns inverseMixColumns;
        InverseShiftRows inverseShiftRows;
        keyExpansion.run(key,ExpandedKey);

        for(int i = 14;i>=1;--i){
            addRoundKey(i);
            if(i!=14){
                inverseMixColumns.run(state);
            }
            inverseShiftRows.run(state);
            inverseSuBytes.runForState(state);
        }

        addRoundKey(0);

        return stateToHexVector();


    }


};
