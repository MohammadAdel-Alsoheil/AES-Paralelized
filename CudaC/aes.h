#ifndef AES_H
#define AES_H

#include <stdint.h>

// Define AES block size and constants
#define AES_BLOCK_SIZE 16
#define AES_ROUNDS_128 10
#define AES_ROUNDS_256 14
#define AES_ROUND_KEY_SIZE_256 (AES_BLOCK_SIZE * (AES_ROUNDS_256 + 1))
#define AES_ROUND_KEY_SIZE_128 (AES_BLOCK_SIZE * (AES_ROUNDS_128 + 1))

#ifdef __cplusplus
extern "C" {
#endif

    /**
     * Perform AES-256 key expansion (key schedule).
     *
     * @param key         Pointer to the 256-bit key (32 bytes).
     * @param roundkeys   Output buffer for expanded round keys (240 bytes).
     */
    void aes_key_schedule_256(const uint8_t *key, uint8_t *roundkeys);

    /**
     * Perform AES-128 key expansion (key schedule).
     *
     * @param key         Pointer to the 128-bit key (16 bytes).
     * @param roundkeys   Output buffer for expanded round keys (176 bytes).
     */
    void aes_key_schedule_128(const uint8_t *key, uint8_t *roundkeys);

    /**
     * Encrypt a single block of data using AES-256.
     *
     * @param roundkeys   The expanded round keys.
     * @param plaintext   The plaintext block to encrypt (16 bytes).
     * @param ciphertext  The output encrypted block (16 bytes).
     */
    void aes_encrypt_256(const uint8_t *roundkeys, const uint8_t *plaintext, uint8_t *ciphertext);

    /**
     * Encrypt a single block of data using AES-128.
     *
     * @param roundkeys   The expanded round keys.
     * @param plaintext   The plaintext block to encrypt (16 bytes).
     * @param ciphertext  The output encrypted block (16 bytes).
     */
    void aes_encrypt_128(const uint8_t *roundkeys, const uint8_t *plaintext, uint8_t *ciphertext);

    /**
     * Decrypt a single block of data using AES-128.
     *
     * @param roundkeys   The expanded round keys.
     * @param ciphertext  The encrypted block to decrypt (16 bytes).
     * @param plaintext   The output decrypted block (16 bytes).
     */
    void aes_decrypt_128(const uint8_t *roundkeys, const uint8_t *ciphertext, uint8_t *plaintext);

#ifdef __cplusplus
}
#endif

#endif // AES_H
