//
// Created by ahmad on 12/1/2024.
//

#include <vector>
#include <algorithm>

using namespace std;

class InverseShiftRows{
private:
    int SIZE=4;
public:
    void run(vector<vector<unsigned char>>& state){

        for (int row = 1; row < SIZE; ++row) {
            std::rotate(state[row].begin(), state[row].end() - row, state[row].end());
        }
    }
};