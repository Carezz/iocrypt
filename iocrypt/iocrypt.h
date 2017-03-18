#pragma once
#include<stdint.h>
#include<stdio.h>
#include<windows.h>

#include "crypto/rng/entropy.h"
#include "crypto/rng/ctr_drbg.h"
#include "crypto/kdf/hkdf/hkdf.h"
#include "crypto/hashes/sha256/sha256.h"
#include "crypto/aes/aes.h"

#define CIPHERKEY_BITS 256
#define CIPHERKEY_SIZE CIPHERKEY_BITS / 8

#define IV_BITS 128
#define IV_SIZE IV_BITS / 8

#define HMACKEY_BITS 256
#define HMACKEY_SIZE HMACKEY_BITS / 8

#define HASH_BITS 256
#define HASH_SIZE HASH_BITS / 8

#define SALT_BITS 128
#define SALT_SIZE SALT_BITS / 8

#define HEADER_MASTER_SIZE CIPHERKEY_SIZE + IV_SIZE
#define HEADER_SIZE SALT_SIZE + HASH_SIZE + SALT_SIZE + HEADER_MASTER_SIZE

#define FILE_BUF_SIZE 4096

#define IOCRYPT_SUCCESS 1
#define IOCRYPT_ERROR 0

#define IOCRYPT_ENCRYPT 1
#define IOCRYPT_DECRYPT 0

#define PRNG_CUSTOM "iocrypt randomization"
#define KDF_CUSTOM "iocrypt key-derivation function"

#define INPUT_FILE_MODE "rb"
#define OUTPUT_FILE_MODE "wb"
#define IOCRYPT_EXT ".enc"

#pragma pack(1)
typedef struct
{
  uint8_t hmac_key[HMACKEY_SIZE];
  uint8_t header_key[CIPHERKEY_SIZE];
  uint8_t header_iv[IV_SIZE];
  uint8_t master_key[CIPHERKEY_SIZE];
  uint8_t master_iv[CIPHERKEY_SIZE];
}iocrypt_keys_context;
#pragma pack()

typedef struct
{
  FILE* in;
  uint64_t in_len;
  uint64_t file_blocks;
  uint32_t final_block;
  FILE* out;

  uint8_t path_name[MAX_PATH];
  uint8_t file_buf[FILE_BUF_SIZE];
  uint32_t type;
}iocrypt_file_context;

typedef struct
{
  iocrypt_file_context file;
  uint8_t* passphrase;
  uint32_t passphrase_len;
  mbedtls_md_context_t hash;
  mbedtls_aes_context cipher;
  iocrypt_keys_context keys;
  uint8_t iocrypt_header[HEADER_SIZE];

  /* AES-CTR specific */
  uint8_t stream[16];
  size_t offset;
}iocrypt_context;

uint32_t iocrypt_init(iocrypt_context* ctx, uint8_t* passphrase, uint32_t passphrase_len);
uint32_t iocrypt_crypt_dir(iocrypt_context* ctx, uint32_t type, uint8_t* dir_path, uint32_t dir_path_len);
uint32_t iocrypt_crypt(iocrypt_context* ctx, uint32_t type, uint8_t* file_path, uint32_t file_path_len);
void iocrypt_free(iocrypt_context* ctx);
