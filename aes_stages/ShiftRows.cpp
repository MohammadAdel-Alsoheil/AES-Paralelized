//
// Created by ahmad on 12/1/2024.
//

#include <vector>
#include <algorithm>
#include "../Utils.h"


class ShiftRows{
private:
    int SIZE=4;
public:
    void run(vector<ByteVector>& state){

        for (int row = 1; row < SIZE; ++row) {
            rotate(state[row].begin(), state[row].begin() + row, state[row].end());
        }
    }
};