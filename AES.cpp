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

        vector<unsigned char> decrypt(vector<unsigned char> cipherText, vector<unsigned char> givenKey){
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

        // for testing
        // void displayExpandedKey() const {
        //     cout << "Expanded Key:\n";
        //     for (int i = 0; i < ExpandedKey.size(); ++i) {
        //         cout << "Word " << i << ": ";
        //         for (unsigned char byte : ExpandedKey[i]) {
        //             cout << hex << (int)byte << " ";
        //         }
        //         cout << "\n";
        //     }
        // }

        // for testing
        // std::string vectorToHexString(const std::vector<unsigned char>& data) {
        //     std::ostringstream oss;

        //     for (unsigned char byte : data) {
        //         // Convert each byte to a two-character hexadecimal representation
        //         oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        //     }

        //     return oss.str();
        // }

        

};

// int main(){
//     AES aes;
//     vector<unsigned char> data = {
//         0x00, 0x11, 0x22, 0x33,
//         0x44, 0x55, 0x66, 0x77,
//         0x88, 0x99, 0xaa, 0xbb,
//         0xcc, 0xdd, 0xee, 0xff
//     };

//     vector<unsigned char> key = {
//         0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
//         0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
//         0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
//         0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
//     };


//     vector<unsigned char> A = aes.encrypt(data, key);
//     cout << aes.vectorToHexString(A) << "\n";

//     vector<unsigned char> B = aes.decrypt(A, key);
//     cout << aes.vectorToHexString(B) << "\n";

//     return 0;
// }
