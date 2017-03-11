#include "iocrypt.h"

static void secure_erase(void* data, uint64_t len)
{
   if(data == NULL || len == 0) return;

   volatile unsigned char* p = (volatile unsigned char*)data;
   while(len--) *p++ = 0;
}

static uint32_t iocrypt_gen_keys(iocrypt_context* ctx)
{
    uint32_t err = 0;
	mbedtls_entropy_context entropy;
	mbedtls_entropy_init(&entropy);

	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ctr_drbg_init(&ctr_drbg);

	if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, PRNG_CUSTOM, sizeof(PRNG_CUSTOM)) != 0)
	{
	   err = 1;
	   goto cleanup;
	}

	if (mbedtls_ctr_drbg_random(&ctr_drbg, ctx->keys.header_masterkey, HEADER_BLOCK_SIZE) != 0)
	{
	   err = 1;
	   goto cleanup;
	}

	if (mbedtls_ctr_drbg_random(&ctr_drbg, ctx->iocrypt_header, SALT_SIZE) != 0)
	{
		err = 1;
		goto cleanup;
	}

	if (mbedtls_ctr_drbg_random(&ctr_drbg, ctx->iocrypt_header + SALT_SIZE + HASH_SIZE, SALT_SIZE) != 0)
	{
		err = 1;
		goto cleanup;
	}

cleanup:
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);

	if(err) return IOCRYPT_ERROR;

	return IOCRYPT_SUCCESS;
}

static uint32_t iocrypt_derive_keys(iocrypt_context* ctx, uint32_t type)
{
	if (ctx == NULL)
		return IOCRYPT_ERROR;

	uint32_t err = 0;
	uint8_t* input = NULL, *output = NULL;

	if (type && !iocrypt_gen_keys(ctx))
	{
		err = 1;
		goto cleanup;
	}

	if (mbedtls_hkdf(ctx->md_info, ctx->iocrypt_header, SALT_SIZE, ctx->passphrase, ctx->passphrase_len,
		KDF_CUSTOM, sizeof(KDF_CUSTOM), ctx->keys.hmac_key, HMACKEY_SIZE) != 0)
	{
		err = 1;
		goto cleanup;
	}

	if (mbedtls_hkdf(ctx->md_info, ctx->iocrypt_header + SALT_SIZE + HASH_SIZE, SALT_SIZE, ctx->passphrase, ctx->passphrase_len,
		KDF_CUSTOM, sizeof(KDF_CUSTOM), ctx->keys.header_prekey, HEADER_BLOCK_SIZE) != 0)
	{
		err = 1;
		goto cleanup;
	}

	if (type)
	{
		input = ctx->keys.header_masterkey;
		output = ctx->iocrypt_header + SALT_SIZE + HASH_SIZE + SALT_SIZE;
	}
	else
	{
		input = ctx->iocrypt_header + SALT_SIZE + HASH_SIZE + SALT_SIZE;
		output = ctx->keys.header_masterkey;
	}

	if (mbedtls_aes_setkey_enc(&ctx->cipher, ctx->keys.header_prekey, CIPHERKEY_BITS) != 0)
	{
		err = 1;
		goto cleanup;
	}

	if (mbedtls_aes_crypt_ctr(&ctx->cipher, HEADER_BLOCK_SIZE, &ctx->offset, ctx->keys.header_prekey + CIPHERKEY_SIZE, ctx->stream, input, output) != 0)
	{
		err = 1;
		goto cleanup;
	}

cleanup:
	mbedtls_aes_free(&ctx->cipher);
	input = NULL;
	output = NULL;

	if(err) return IOCRYPT_ERROR;

	return IOCRYPT_SUCCESS;
}

static uint32_t iocrypt_process(iocrypt_context* ctx, uint32_t type, uint32_t overwrite)
{
	uint32_t err = 0;
	uint8_t content_block[CONTENT_BLOCK_SIZE] = {0};
	// needs error checking
	fseek(ctx->f, 0, SEEK_END);
	uint64_t file_len = ftell(ctx->f);
	rewind(ctx->f);

	uint64_t block_size = file_len / CONTENT_BLOCK_SIZE;
	uint32_t final_block = file_len % CONTENT_BLOCK_SIZE;
	
	if(mbedtls_aes_setkey_enc(&ctx->cipher, ctx->keys.header_masterkey, CIPHERKEY_BITS) != 0)
	{
		err = 1;
		goto cleanup;
	}

	if (type && fwrite(ctx->iocrypt_header, 1, HEADER_SIZE, ctx->o) != HEADER_SIZE)
	{
		err = 1;
		goto cleanup;
	}

	while (block_size--)
	{
	    if(fread(content_block, 1, CONTENT_BLOCK_SIZE, ctx->f) != CONTENT_BLOCK_SIZE)
		{
			err = 1;
			goto cleanup;
		}

		if (mbedtls_aes_crypt_ctr(&ctx->cipher, CONTENT_BLOCK_SIZE, &ctx->offset, ctx->keys.header_masterkey + IV_SIZE, ctx->stream,
		   content_block, content_block) != 0)
		{
			err = 1;
			goto cleanup;
		}

		if (fwrite(content_block, 1, CONTENT_BLOCK_SIZE, ctx->o) != CONTENT_BLOCK_SIZE)
		{
			err = 1;
			goto cleanup;
		}
	}

	if (final_block)
	{
		if (fread(content_block, 1, CONTENT_BLOCK_SIZE, ctx->f) != CONTENT_BLOCK_SIZE)
		{
			err = 1;
			goto cleanup;
		}

		if (mbedtls_aes_crypt_ctr(&ctx->cipher, final_block, &ctx->offset, ctx->keys.header_masterkey + IV_SIZE, ctx->stream,
			content_block, content_block) != 0)
		{
			err = 1;
			goto cleanup;
		}

		if (fwrite(content_block, 1, CONTENT_BLOCK_SIZE, ctx->o) != CONTENT_BLOCK_SIZE)
		{
			err = 1;
			goto cleanup;
		}
	}

cleanup:
	file_len = 0;
	final_block = 0;
	secure_erase(content_block, CONTENT_BLOCK_SIZE);

	if(err) return IOCRYPT_ERROR;

	return IOCRYPT_SUCCESS;
}

uint32_t iocrypt_init(iocrypt_context* ctx, uint8_t* passphrase, uint32_t passphrase_len)
{
    if(ctx == NULL || passphrase == NULL || passphrase_len == 0)
	    return IOCRYPT_ERROR;

	ctx->md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

	if (ctx->md_info == NULL)
		return IOCRYPT_ERROR;

	mbedtls_md_init(&ctx->hash);

	if(mbedtls_md_setup(&ctx->hash, ctx->md_info, 1) != 0)
	    return IOCRYPT_ERROR;

	mbedtls_aes_init(&ctx->cipher);
	secure_erase(ctx->stream, sizeof(ctx->stream));
	secure_erase(&ctx->keys, sizeof(keys_context));
	secure_erase(ctx->iocrypt_header, HEADER_SIZE);
	ctx->passphrase = passphrase;
	ctx->passphrase_len = passphrase_len;
	ctx->offset = 0;
	ctx->f = NULL;
	ctx->o = NULL;
	return IOCRYPT_SUCCESS;
}

uint32_t iocrypt_crypt_dir(iocrypt_context* ctx, uint32_t type, uint8_t* dir_path, uint32_t dir_path_len)
{
   if(dir_path == NULL || !dir_path_len)
      return IOCRYPT_ERROR;
   


   return IOCRYPT_SUCCESS;
}

uint32_t iocrypt_crypt(iocrypt_context* ctx, uint32_t type, uint32_t overwrite, uint8_t* file_path, uint32_t file_path_len)
{
	if (ctx == NULL || file_path == NULL || !file_path_len)
		return IOCRYPT_ERROR;

	uint32_t err = 0;
    // file_path_len unused, output is just for alpha testing.
	ctx->f = fopen(file_path, INPUT_FILE_MODE);

	if (ctx->f == NULL)
	{
	   err = 1;
	   goto cleanup;
	}

	ctx->f = fopen(TEST_OUTPUT_NAME, OUTPUT_FILE_MODE);

	if (ctx->f == NULL)
	{
		err = 1;
		goto cleanup;
	}

	if (!type && fread(ctx->iocrypt_header, 1, HEADER_SIZE, ctx->f) != HEADER_SIZE) // decrypting
	{
		err = 1;
		goto cleanup;
	}

	if (!iocrypt_derive_keys(ctx, type))
	{
		err = 1;
		goto cleanup;
	}

	if (!iocrypt_process(ctx, type, 0))
	{
		err = 1;
		goto cleanup;
	}

cleanup:
    fclose(ctx->f);
	fclose(ctx->o);
	if(err) return IOCRYPT_ERROR;

	return IOCRYPT_SUCCESS;
}

void iocrypt_free(iocrypt_context* ctx)
{
   if(ctx == NULL) return;

   ctx->f = NULL;
   ctx->o = NULL;
   ctx->md_info = NULL;
   mbedtls_md_free(&ctx->hash);
   mbedtls_aes_free(&ctx->cipher);
   secure_erase(ctx->stream, sizeof(ctx->stream));
   secure_erase(&ctx->keys, sizeof(ctx->keys));
   secure_erase(&ctx->iocrypt_header, HEADER_SIZE);
   secure_erase(ctx->passphrase, ctx->passphrase_len);
   ctx->passphrase_len = 0;
   ctx->offset = 0;
}