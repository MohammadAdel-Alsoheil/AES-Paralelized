//
// Created by ahmad on 12/1/2024.
//

#include <iostream>
#include <cmath>
#include <ctime>
#include <random>
#include <vector>

using namespace std;

class MixColumns{
private:
    vector<vector<unsigned char>> MIX_MATRIX = {
            {0x02, 0x03, 0x01, 0x01},
            {0x01, 0x02, 0x03, 0x01},
            {0x01, 0x01, 0x02, 0x03},
            {0x03, 0x01, 0x01, 0x02}
    };
    unsigned char gmul(unsigned char a, unsigned char b) {
        unsigned char p = 0; // The product
        while (b) {
            if (b & 1) p ^= a; // If the least significant bit of b is set, add a to p
            bool high_bit_set = a & 0x80; // Check if the high bit of a is set
            a <<= 1; // Multiply a by 2
            if (high_bit_set) a ^= 0x1B; // XOR with the AES irreducible polynomial if needed
            b >>= 1; // Divide b by 2
        }
        return p;
    }
public:
    void run(vector<vector<unsigned char>>& state){
        for (int col = 0; col < 4; ++col) {
            vector<unsigned char> tempColumn(4);
            for (int row = 0; row < 4; ++row) {
                tempColumn[row] =
                        gmul(state[0][col], MIX_MATRIX[row][0]) ^
                        gmul(state[1][col], MIX_MATRIX[row][1]) ^
                        gmul(state[2][col], MIX_MATRIX[row][2]) ^
                        gmul(state[3][col], MIX_MATRIX[row][3]);
            }
            for (int row = 0; row < 4; ++row) {
                state[row][col] = tempColumn[row];
            }
        }
    }
};