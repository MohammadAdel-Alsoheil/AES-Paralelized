#include <iostream>
#include <cmath>
#include <ctime>
#include <random>
#include <vector>
#include <iomanip>
#include <cstring>
#include "KeyExpansion.cpp"
#include "MixColumns.cpp"
#include "ShiftRows.cpp"
#include "InverseSubBytes.cpp"
#include "InverseMixColumns.cpp"
#include "InverseShiftRows.cpp"

using namespace std;

constexpr int SIZE = 4;
constexpr int KEYSIZE = 32;

class AES{
    
    private:
        vector<unsigned char> key; // 256 bits or 32 bytes 
        vector<vector<unsigned char>> ExpandedKey{WORDCOUNT, vector<unsigned char>(4)}; // 60 words or 240 bytes
        vector<vector<unsigned char>> state{4,vector<unsigned  char>(4)};

        void addRoundKey(int roundNumber){ //correct

            int start = roundNumber * 4; // 0 for 1st round 
            for (int i = 0; i < 4; ++i) {
                for (int j = 0; j < 4; ++j) {
                    state[j][i] = state[j][i] ^ ExpandedKey[start +i][j]; //changed this to (j,i)
                    
                }
            }
        }

        vector<unsigned char> generateKey(){
            vector<unsigned char> generatedKey;
            random_device rd;
            mt19937 gen(rd());
            uniform_int_distribution<> dis(0, 255);

            for(int i = 0;i<KEYSIZE;++i){
                generatedKey.push_back(static_cast<unsigned char>(dis(gen)));
            }

            return generatedKey;
        }
        void convertToStateMatrix(vector<unsigned char> bytes) {
            // std::vector<unsigned char> bytes;

            // Convert the plaintext from hexadecimal string to bytes
            // for (size_t i = 0; i < plaintext.length(); i += 2) {
            //     std::string byteString = plaintext.substr(i, 2); // Extract two characters at a time
            //     unsigned int byte;
            //     std::istringstream(byteString) >> std::hex >> byte;
            //     bytes.push_back(static_cast<unsigned char>(byte));
            // }

            // Define the dimensions of the state matrix
            size_t rows = 4, cols = 4;

            // Fill the state matrix from the bytes vector, but represent the word in column
            for (size_t i = 0; i < bytes.size(); ++i) {
                size_t col = i / rows; // Map bytes to columns first
                size_t row = i % rows; // Then map to rows within the column
                state[row][col] = bytes[i];
            }

        }
        std::string stateToHexString() {  // correct
            std::ostringstream hexStringStream;

           
            for(int i = 0;i<4;++i){
                for(int j = 0;j<4;++j){
                    hexStringStream << std::hex << std::setw(2) << std::setfill('0') << (int)state[j][i];
                }
            }
            return hexStringStream.str();
        }

        vector<unsigned char> stateToHexVector() {  
            vector<unsigned char> bytes;

           
            for(int i = 0;i<4;++i){
                for(int j = 0;j<4;++j){
                    bytes.push_back(state[j][i]);
                }
            }
            return bytes;
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



    


    public:
        // I moved plainText, key from the constructor so that we can encrypt multiple data from same instance, using different keys
        AES(){
           
        }
        vector<unsigned char> encrypt(vector<unsigned char> plainText, vector<unsigned char> givenKey){
            key = givenKey;
            convertToStateMatrix(plainText);
            KeyExpansion keyExpansion; 
            SubBytes subBytes;
            ShiftRows shiftRows;
            MixColumns mixColumns;
            keyExpansion.run(key,ExpandedKey); // correct
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
};
