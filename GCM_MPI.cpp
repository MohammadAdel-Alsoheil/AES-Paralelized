//
// Created by ahmad on 12/4/2024.
//
#include <iostream>
#include <vector>
#include <cmath>
#include <string>
#include <stdexcept>
#include <bitset>
#include "AES.cpp"
#include "Ghash.h"
#include <mpi.h>
using namespace Utils;


class GCM_MPI {
private:
    ByteVector key;
    ByteVector IV;
    ByteVector AAD;
    int size, rank;
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
    void incrementCounter(ByteVector& counter, uint32_t increment) {
        // Last 4 bytes represent the counter (counter[12] to counter[15])
        for (int i = 15; i >= 12; --i) {
            // Add the least significant byte of the increment
            uint32_t temp = counter[i] + (increment & 0xFF);
            counter[i] = temp & 0xFF;       // Keep only the least significant byte
            increment = temp >> 8;         // Carry over the overflow to the next byte

            // If there's no carry left, we can break early
            if (increment == 0) {
                break;
            }
        }
    }

    vector<ByteVector> GCTR(ByteVector ICB, ByteVector val) {
        AES aes(key);
        ByteVector CB = ICB;
        vector<ByteVector> X = nest(val, 16);
        vector<ByteVector> local_res;

        int world_size, world_rank;
        MPI_Comm_size(MPI_COMM_WORLD, &world_size);
        MPI_Comm_rank(MPI_COMM_WORLD, &world_rank);

        int total_blocks = X.size();
        int blocks_per_proc = (total_blocks + world_size - 1) / world_size;
        int start_block = world_rank * blocks_per_proc;
        int end_block = std::min(start_block + blocks_per_proc, total_blocks);

        if (start_block >= total_blocks) {
            start_block = end_block = 0;
        }

        // Compute the counter for the starting block
        ByteVector CB_local = CB;
        incrementCounter(CB_local, start_block);

        for (int i = start_block; i < end_block; ++i) {
            ByteVector Y = xorF(aes.encrypt(CB_local), X[i]);
            incrementCounter(CB_local);
            local_res.push_back(Y);
        }

        ByteVector local_res_flat = Utils::flatten(local_res);

        int local_size = local_res_flat.size();
        std::vector<int> recvcounts(world_size, 0);
        MPI_Gather(&local_size, 1, MPI_INT, recvcounts.data(), 1, MPI_INT, 0, MPI_COMM_WORLD);

        int total_size = 0;
        std::vector<int> displs(world_size, 0);
        if (world_rank == 0) {
            displs[0] = 0;
            for (int i = 1; i < world_size; ++i) {
                displs[i] = displs[i - 1] + recvcounts[i - 1];
            }
            total_size = displs[world_size - 1] + recvcounts[world_size - 1];
        }

        ByteVector global_res_flat(total_size);
        MPI_Gatherv(local_res_flat.data(), local_size, MPI_UNSIGNED_CHAR,
                    global_res_flat.data(), recvcounts.data(), displs.data(),
                    MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);

        if (world_rank == 0) {
            return Utils::nest(global_res_flat, 16);
        }

        return vector<ByteVector>();
    }




    ByteVector GHASH(ByteVector val, ByteVector H){
        ByteVector Y0 = ByteVector(16, 0x00);
        vector<ByteVector> X = nest(val,16);
        for(int i = 0;i<X.size();++i){
            Y0 = Ghash::gf128Multiply(xorF(Y0, X[i]), H);
        }
        return Y0;
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
    pair<ByteVector, ByteVector> encrypt(const ByteVector key,  const ByteVector IV, const ByteVector AAD,ByteVector P) {
        this->AAD= AAD;
        this->IV = IV;
        this->key = key;
        int size;
        MPI_Comm_size(MPI_COMM_WORLD, &size);

        int rank;
        MPI_Comm_rank(MPI_COMM_WORLD, &rank);
        AES aes(key);
        ByteVector J0,H;
        if(rank==0){

            H = aes.encrypt(ByteVector(16, 0x00));

            prepareCounter(J0, this->IV);
            incrementCounter(J0);
        }
        int J0_size = (rank == 0) ? J0.size() : 0;
        MPI_Bcast(&J0_size, 1, MPI_INT, 0, MPI_COMM_WORLD);

        J0.resize(J0_size);

        MPI_Bcast(J0.data(), J0_size, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);

        vector<ByteVector> C = GCTR(J0, P);
        ByteVector newC, S;
        if(rank==0){
            newC = flatten(C);

            newC.pop_back();
            int sizeOfCinBits = newC.size()*8;
            int sizeofAADinBits = AAD.size()*8;


            int u = (128*ceil((double) sizeOfCinBits/128)) - sizeOfCinBits;
            int v = (128*ceil((double) sizeofAADinBits/128)) - sizeofAADinBits;


            S = GHASH(padC(newC,u,v, sizeOfCinBits,sizeofAADinBits ), H);
            prepareCounter(J0, this->IV);
        }

        vector<ByteVector> T = GCTR(J0,S);
        ByteVector newT = flatten(T);


        return { newC, newT };
    }


};

int main(int argc, char *argv[]){
    MPI_Init(&argc, &argv);

    // Key (16 bytes)
    ByteVector Key = {
            0x4C, 0x97, 0x3D, 0xBC, 0x73, 0x64, 0x62, 0x16,
            0x74, 0xF8, 0xB5, 0xB8, 0x9E, 0x5C, 0x15, 0x51,
            0x1F, 0xCE, 0xD9, 0x21, 0x64, 0x90, 0xFB, 0x1C,
            0x1A, 0x2C, 0xAA, 0x0F, 0xFE, 0x04, 0x07, 0xE5
    };
    // P (Plaintext, 64 bytes)
    ByteVector P = {};

    for(int i =0;i<50000;i++){
        P.push_back(0x00);
    }

    // IV (Initialization Vector, 12 bytes)
    ByteVector IV = {
            0x7A, 0xE8, 0xE2, 0xCA, 0x4E, 0xC5, 0x00, 0x01,
            0x2E, 0x58, 0x49, 0x5C
    };

    // A (Associated Data, 20 bytes)
    ByteVector A = {
            0x68, 0xF2, 0xE7, 0x76, 0x96, 0xCE, 0x7A, 0xE8,
            0xE2, 0xCA, 0x4E, 0xC5, 0x88, 0xE5, 0x4D, 0x00,
            0x2E, 0x58, 0x49, 0x5C
    };
    double start_time = MPI_Wtime();

    GCM_MPI gcm;
    pair<ByteVector, ByteVector> res = gcm.encrypt(Key, IV, A,P);
    double end_time = MPI_Wtime();
    double elapsed_time = end_time - start_time;

    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    if(rank==0){
//        cout << "Cipher Text: " + bytesToHex(res.first) << "\n";
//        cout << "Added Tag: " + bytesToHex(res.second) << "\n";
        std::cout << "Time: " << elapsed_time << " seconds" << std::endl;

    }

    MPI_Finalize();

    return 0;
}
