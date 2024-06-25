/*
 * Crypto_HMAC.c
 *
 *  Created on: Jun 24, 2024
 *      Author: abdel
 */

#include "Crypto_HMAC.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


// Private function declarations
static void pad_message(const uint8_t *input_data, size_t input_len, uint8_t *output_message, size_t output_len, uint8_t pad_byte);
static void compute_hmac_sha256(const uint8_t *message, size_t message_len, uint8_t *output_hmac, const uint8_t *key);
static void prepare_data(Crypto_HMAC_Context *ctx, const uint8_t *data, size_t data_len, uint8_t *output_buffer, size_t buffer_len);
static int check_freshness_value(Crypto_HMAC_Context *ctx, uint8_t received_freshness);
static int extract_data_and_hmac(Crypto_HMAC_Context *ctx, const uint8_t *buffer, size_t buffer_len, uint8_t *data, size_t data_len, uint8_t *truncated_hmac, size_t truncated_hmac_len);

// Function to pad the message with a specified byte up to a fixed length
static void pad_message(const uint8_t *input_data, size_t input_len, uint8_t *output_message, size_t output_len, uint8_t pad_byte) {
    memcpy(output_message, input_data, input_len);
    memset(output_message + input_len, pad_byte, output_len - input_len);
}

// Function to compute HMAC-SHA256 over a 64-byte message
static void compute_hmac_sha256(const uint8_t *message, size_t message_len, uint8_t *output_hmac, const uint8_t *key) {
    mbedtls_md_context_t ctx;
    const mbedtls_md_info_t *info;

    mbedtls_md_init(&ctx);
    info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_setup(&ctx, info, 1);

    mbedtls_md_hmac_starts(&ctx, key, 32);
    mbedtls_md_hmac_update(&ctx, message, message_len);
    mbedtls_md_hmac_finish(&ctx, output_hmac);

    mbedtls_md_free(&ctx);
}

// Prepare the data buffer for HMAC calculation
static void prepare_data(Crypto_HMAC_Context *ctx, const uint8_t *data, size_t data_len, uint8_t *output_buffer, size_t buffer_len) {
#if USE_FRESHNESS_VALUE
    if (buffer_len < data_len + 1) {
        //Error Handeling
        return;
    }

    memcpy(output_buffer, data, data_len);
    output_buffer[data_len] = ctx->freshness_counter++;
#else
    if (buffer_len < data_len) {
        //Error Handeling
        return;
    }

    memcpy(output_buffer, data, data_len);
#endif

    pad_message(output_buffer, data_len + (USE_FRESHNESS_VALUE ? 1 : 0), output_buffer, buffer_len, 0x00);
}

// Check the freshness value against the current freshness counter
static int check_freshness_value(Crypto_HMAC_Context *ctx, uint8_t received_freshness) {
    return received_freshness == ctx->freshness_counter - 1;
}

// Extract data and truncated HMAC from the received buffer
static int extract_data_and_hmac(Crypto_HMAC_Context *ctx, const uint8_t *buffer, size_t buffer_len, uint8_t *data, size_t data_len, uint8_t *truncated_hmac, size_t truncated_hmac_len) {
    if (buffer_len < data_len + truncated_hmac_len + (USE_FRESHNESS_VALUE ? 1 : 0)) {
        //Error Handeling
        return 0;
    }

    memcpy(data, buffer, data_len);

#if USE_FRESHNESS_VALUE
    if (buffer[data_len] != ctx->freshness_counter - 1) {
        //Error Handeling
        return 0;
    }
#endif

    size_t offset = data_len + (USE_FRESHNESS_VALUE ? 1 : 0);
    memcpy(truncated_hmac, buffer + offset, truncated_hmac_len);

    return 1;
}

// Initialize the HMAC context with the shared key
void Crypto_HMAC_Init(Crypto_HMAC_Context *ctx, const uint8_t *shared_key) {
    memcpy(ctx->key, shared_key, 32);
    ctx->freshness_counter = 0;
}

// Calculate HMAC-SHA256 for variable-sized data
void Crypto_HMAC_Calculate(Crypto_HMAC_Context *ctx, const uint8_t *input_data, size_t input_len, uint8_t *output_hmac) {
    uint8_t padded_message[64];
    prepare_data(ctx, input_data, input_len, padded_message, 64);
    compute_hmac_sha256(padded_message, 64, output_hmac, ctx->key);
}

// Create a buffer to be sent with the truncated HMAC
void Crypto_HMAC_CreateSendBuffer(Crypto_HMAC_Context *ctx, uint8_t *buffer, size_t buffer_len, const uint8_t *data, size_t data_len, const uint8_t *full_hmac, size_t truncated_hmac_len) {
    if (buffer_len < data_len + truncated_hmac_len + (USE_FRESHNESS_VALUE ? 1 : 0)) {
        //Error Handeling
        return;
    }

    memcpy(buffer, data, data_len);

#if USE_FRESHNESS_VALUE
    buffer[data_len] = ctx->freshness_counter - 1;
#endif

    memcpy(buffer + data_len + (USE_FRESHNESS_VALUE ? 1 : 0), full_hmac, truncated_hmac_len);
}

// Prepare the buffer to be sent with data, freshness value, and truncated HMAC
void Crypto_HMAC_PrepareSendBuffer(Crypto_HMAC_Context *ctx, const uint8_t *data, size_t data_len, uint8_t *send_buffer, size_t buffer_len, size_t truncated_hmac_len) {
    uint8_t full_hmac[32];
    Crypto_HMAC_Calculate(ctx, data, data_len, full_hmac);
    Crypto_HMAC_CreateSendBuffer(ctx, send_buffer, buffer_len, data, data_len, full_hmac, truncated_hmac_len);
}

// Verify the receive buffer and return 1 (valid) or 0 (invalid)
int Crypto_HMAC_VerifyReceiveBuffer(Crypto_HMAC_Context *ctx, const uint8_t *receive_buffer, size_t buffer_len, size_t data_len, size_t truncated_hmac_len) {
    uint8_t extracted_data[data_len];
    uint8_t extracted_truncated_hmac[truncated_hmac_len];
    uint8_t calculated_hmac[32];

    if (!extract_data_and_hmac(ctx, receive_buffer, buffer_len, extracted_data, data_len, extracted_truncated_hmac, truncated_hmac_len)) {
        return 0;
    }

#if USE_FRESHNESS_VALUE
    if (!check_freshness_value(ctx, receive_buffer[data_len])) {
        return 0;
    }
#endif

    Crypto_HMAC_Calculate(ctx, extracted_data, data_len, calculated_hmac);
    return (memcmp(extracted_truncated_hmac, calculated_hmac, truncated_hmac_len) == 0);
}

// Extract the actual data from the receive buffer without freshness value
void Crypto_HMAC_ExtractDataFromBuffer(Crypto_HMAC_Context *ctx, const uint8_t *receive_buffer, size_t buffer_len, uint8_t *extracted_data, size_t data_len) {
    if (buffer_len < data_len + (USE_FRESHNESS_VALUE ? 1 : 0)) {
        //Error Handeling
        return;
    }

    memcpy(extracted_data, receive_buffer, data_len);
}

