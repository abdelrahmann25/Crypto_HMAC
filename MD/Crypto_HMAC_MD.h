/*
 * Crypto_HMAC.h
 *
 *  Created on: Jun 24, 2024
 *      Author: abdel
 */

#ifndef CRYPTO_HMAC_CRYPTO_HMAC_H_
#define CRYPTO_HMAC_CRYPTO_HMAC_H_

#include <stdint.h>
#include <stddef.h>
#include "md.h"

// Define a macro to determine if the freshness value is used or not
#define USE_FRESHNESS_VALUE 1

// Structure for HMAC context
typedef struct {
    uint8_t key[32]; // Shared key (32 bytes for HMAC-SHA256)
    uint8_t freshness_counter; // Freshness value counter
} Crypto_HMAC_Context;

// Initialize the HMAC context with the shared key
void Crypto_HMAC_Init(Crypto_HMAC_Context *ctx, const uint8_t *shared_key);

// Prepare the buffer to be sent with data, freshness value, and truncated HMAC
void Crypto_HMAC_PrepareSendBuffer(Crypto_HMAC_Context *ctx, const uint8_t *data, size_t data_len, uint8_t *send_buffer, size_t buffer_len, size_t truncated_hmac_len);

// Verify the receive buffer and return 1 (valid) or 0 (invalid)
int Crypto_HMAC_VerifyReceiveBuffer(Crypto_HMAC_Context *ctx, const uint8_t *receive_buffer, size_t buffer_len, size_t data_len, size_t truncated_hmac_len);

// Extract the actual data from the receive buffer without freshness value
void Crypto_HMAC_ExtractDataFromBuffer(Crypto_HMAC_Context *ctx, const uint8_t *receive_buffer, size_t buffer_len, uint8_t *extracted_data, size_t data_len);

#endif // HMAC_H

