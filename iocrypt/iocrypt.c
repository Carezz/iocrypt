#include "iocrypt.h"

/* crypto */

static void secure_erase(void* data, uint64_t len)
{
   if(data == NULL || len == 0) return;

   volatile unsigned char* p = (volatile unsigned char*)data;
   while(len--) *p++ = 0;
}

static uint32_t iocrypt_gen_keys(iocrypt_keys_context* keys, uint8_t* iocrypt_header)
{
    uint32_t res = IOCRYPT_SUCCESS;
	mbedtls_entropy_context entropy;
	mbedtls_entropy_init(&entropy);

	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ctr_drbg_init(&ctr_drbg);

	if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, PRNG_CUSTOM, sizeof(PRNG_CUSTOM)) != 0)
	{
	   res = IOCRYPT_ERROR;
	   goto cleanup;
	}

	if (mbedtls_ctr_drbg_random(&ctr_drbg, keys->master_key, HEADER_MASTER_SIZE) != 0)
	{
	   res = IOCRYPT_ERROR;
	   goto cleanup;
	}

	if (mbedtls_ctr_drbg_random(&ctr_drbg, iocrypt_header, SALT_SIZE) != 0)
	{
		res = IOCRYPT_ERROR;
		goto cleanup;
	}

	if (mbedtls_ctr_drbg_random(&ctr_drbg, iocrypt_header + SALT_SIZE + HASH_SIZE, SALT_SIZE) != 0)
	{
		res = IOCRYPT_ERROR;
		goto cleanup;
	}

cleanup:
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	return res;
}

static uint32_t iocrypt_derive_keys(iocrypt_context* ctx)
{
	uint32_t res = IOCRYPT_SUCCESS;
	uint8_t* input = NULL, *output = NULL;

	if (ctx->file.type == IOCRYPT_ENCRYPT && !iocrypt_gen_keys(&ctx->keys, ctx->iocrypt_header))
	{
		res = IOCRYPT_SUCCESS;
		goto cleanup;
	}

	if (mbedtls_hkdf(ctx->hash.md_info, ctx->iocrypt_header, SALT_SIZE, ctx->passphrase, ctx->passphrase_len,
		KDF_CUSTOM, sizeof(KDF_CUSTOM), ctx->keys.hmac_key, HMACKEY_SIZE) != 0)
	{
		res = IOCRYPT_SUCCESS;
		goto cleanup;
	}
	
	if (mbedtls_hkdf(ctx->hash.md_info, ctx->iocrypt_header + SALT_SIZE + HASH_SIZE, SALT_SIZE, ctx->passphrase, ctx->passphrase_len,
		KDF_CUSTOM, sizeof(KDF_CUSTOM), ctx->keys.header_key, HEADER_MASTER_SIZE) != 0)
	{
		res = IOCRYPT_SUCCESS;
		goto cleanup;
	}

	if (ctx->file.type == IOCRYPT_ENCRYPT)
	{
		input = ctx->keys.master_key;
		output = ctx->iocrypt_header + SALT_SIZE + HASH_SIZE + SALT_SIZE;
	}
	else
	{
		input = ctx->iocrypt_header + SALT_SIZE + HASH_SIZE + SALT_SIZE;
		output = ctx->keys.master_key;
	}
	
	if (mbedtls_aes_setkey_enc(&ctx->cipher, ctx->keys.header_key, CIPHERKEY_BITS) != 0)
	{
		res = IOCRYPT_SUCCESS;
		goto cleanup;
	}

	if (mbedtls_aes_crypt_ctr(&ctx->cipher, HEADER_MASTER_SIZE, &ctx->offset, ctx->keys.header_key + CIPHERKEY_SIZE, ctx->stream, input, output) != 0)
	{
		res = IOCRYPT_SUCCESS;
		goto cleanup;
	}

cleanup:
	mbedtls_aes_free(&ctx->cipher);
	input = NULL;
	output = NULL;
	return res;
}

/* file */

static uint32_t iocrypt_file_init(iocrypt_file_context* file, uint8_t* path, uint32_t path_len)
{
	uint32_t res = IOCRYPT_SUCCESS;

	if (path_len >= MAX_PATH - 4)
	{
		res = IOCRYPT_ERROR;
		goto cleanup;
	}

	/* Open input file */

	memcpy(file->path_name, path, path_len);

	file->in = fopen(file->path_name, INPUT_FILE_MODE);

	if (file->in == NULL)
	{
		res = IOCRYPT_ERROR;
		goto cleanup;
	}
	// add check for decryption (remove .enc)
	memcpy(file->path_name + path_len, IOCRYPT_EXT, strlen(IOCRYPT_EXT));

	/* Obtain file length */

	if (fseek(file->in, 0, SEEK_END) != 0)
	{
		res = IOCRYPT_ERROR;
		goto cleanup;
	}

	file->in_len = ftell(file->in);

	if (file->in_len == -1L)
	{
		res = IOCRYPT_ERROR;
		goto cleanup;
	}

	rewind(file->in);

	/* Create output file */

	file->out = fopen(file->path_name, OUTPUT_FILE_MODE);

	if (file->out == NULL)
	{
		res = IOCRYPT_ERROR;
		goto cleanup;
	}

cleanup:
	return res;
}

static uint32_t iocrypt_file_crypt(iocrypt_context* ctx, uint8_t* buf, uint32_t buf_len)
{
	uint32_t res = IOCRYPT_SUCCESS;

	if (fread(buf, 1, buf_len, ctx->file.in) != buf_len)
	{
		res = IOCRYPT_ERROR;
		goto cleanup;
	}

	if (mbedtls_aes_crypt_ctr(&ctx->cipher, buf_len, &ctx->offset, ctx->keys.master_key + IV_SIZE, ctx->stream,
		buf, buf) != 0)
	{
		res = IOCRYPT_ERROR;
		goto cleanup;
	}

	if (mbedtls_md_hmac_update(&ctx->hash, buf, buf_len) != 0)
	{
		res = IOCRYPT_ERROR;
		goto cleanup;
	}

	if (fwrite(buf, 1, CONTENT_BLOCK_SIZE, ctx->file.out) != buf_len)
	{
		res = IOCRYPT_ERROR;
		goto cleanup;
	}

cleanup:
	return res;
}

static void iocrypt_file_free(iocrypt_file_context* file)
{
	if (file->in)
		fclose(file->in);

	if (file->out)
		fclose(file->out);

	secure_erase(file, sizeof(iocrypt_file_context));
}

/* general */

static uint32_t iocrypt_process(iocrypt_context* ctx)
{
	uint32_t res = IOCRYPT_SUCCESS;

	uint8_t content_block[CONTENT_BLOCK_SIZE] = {0};
	uint64_t block_size = ctx->file.in_len / CONTENT_BLOCK_SIZE;
	uint32_t final_block = ctx->file.in_len % CONTENT_BLOCK_SIZE;
	
	if(mbedtls_aes_setkey_enc(&ctx->cipher, ctx->keys.master_key, CIPHERKEY_BITS) != 0)
	{
		res = IOCRYPT_ERROR;
		goto cleanup;
	}

	if (mbedtls_md_hmac_starts(&ctx->hash, ctx->keys.hmac_key, HMACKEY_SIZE) != 0)
	{
		res = IOCRYPT_ERROR;
		goto cleanup;
	}

	if (mbedtls_md_hmac_update(&ctx->hash, ctx->iocrypt_header + SALT_SIZE + HASH_SIZE, HEADER_SIZE - (SALT_SIZE + HASH_SIZE)) != 0)
	{
		res = IOCRYPT_ERROR;
		goto cleanup;
	}

	while (block_size--)
	{
		if (!iocrypt_file_crypt(ctx, content_block, CONTENT_BLOCK_SIZE))
		{
			res = IOCRYPT_ERROR;
			goto cleanup;
		}
	}

	if (final_block)
	{
		if (!iocrypt_file_crypt(ctx, content_block, final_block))
		{
			res = IOCRYPT_ERROR;
			goto cleanup;
		}
	}

	if (mbedtls_md_hmac_finish(&ctx->hash, ctx->iocrypt_header + SALT_SIZE) != 0)
	{
		res = IOCRYPT_ERROR;
		goto cleanup;
	}

	rewind(ctx->file.out);
	// add check for decryption and HMAC verification
	if (ctx->file.type && fwrite(ctx->iocrypt_header, 1, HEADER_SIZE, ctx->file.out) != HEADER_SIZE)
	{
		res = IOCRYPT_ERROR;
		goto cleanup;
	}

cleanup:
	final_block = 0;
	secure_erase(content_block, CONTENT_BLOCK_SIZE);
	return res;
}

/* public */

uint32_t iocrypt_init(iocrypt_context* ctx, uint8_t* passphrase, uint32_t passphrase_len)
{
    if(ctx == NULL || passphrase == NULL || passphrase_len == 0)
	    return IOCRYPT_ERROR;

	const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

	if (md_info == NULL)
		return IOCRYPT_ERROR;

	mbedtls_md_init(&ctx->hash);

	if(mbedtls_md_setup(&ctx->hash, md_info, 1) != 0)
	    return IOCRYPT_ERROR;

	memset(&ctx->file, 0, sizeof(iocrypt_file_context));
	ctx->passphrase = passphrase;
	ctx->passphrase_len = passphrase_len;

	mbedtls_aes_init(&ctx->cipher);
	memset(&ctx->keys, 0, sizeof(iocrypt_keys_context));
	memset(ctx->iocrypt_header, 0, HEADER_SIZE);

	memset(ctx->stream, 0, sizeof(ctx->stream));
	ctx->offset = 0;

	return IOCRYPT_SUCCESS;
}

uint32_t iocrypt_crypt_dir(iocrypt_context* ctx, uint32_t type, uint8_t* dir_path, uint32_t dir_path_len)
{
   if(dir_path == NULL || !dir_path_len)
      return IOCRYPT_ERROR;
   


   return IOCRYPT_SUCCESS;
}

uint32_t iocrypt_crypt(iocrypt_context* ctx, uint32_t type, uint8_t* file_path, uint32_t file_path_len)
{
	if (ctx == NULL || file_path == NULL || !file_path_len)
		return IOCRYPT_ERROR;

	uint32_t res = IOCRYPT_SUCCESS;

	ctx->file.type = type;

	if (!iocrypt_file_init(&ctx->file, file_path, file_path_len))
	{
		res = IOCRYPT_ERROR;
		goto cleanup;
	}

	if (type == IOCRYPT_DECRYPT && fread(ctx->iocrypt_header, 1, HEADER_SIZE, ctx->file.in) != HEADER_SIZE)
	{
		res = IOCRYPT_ERROR;
		goto cleanup;
	}

	if (!iocrypt_derive_keys(ctx))
	{
		res = IOCRYPT_ERROR;
		goto cleanup;
	}

	if (!iocrypt_process(ctx))
	{
		res = IOCRYPT_ERROR;
		goto cleanup;
	}

cleanup:
    if(!res) remove(ctx->file.path_name);
    iocrypt_file_free(&ctx->file);
	return res;
}

void iocrypt_free(iocrypt_context* ctx)
{
   if(ctx == NULL) return;

   secure_erase(&ctx->file, sizeof(iocrypt_file_context));
   ctx->passphrase = NULL;
   ctx->passphrase_len = 0;
   mbedtls_md_free(&ctx->hash);
   mbedtls_aes_free(&ctx->cipher);
   secure_erase(&ctx->keys, sizeof(iocrypt_keys_context));
   secure_erase(&ctx->iocrypt_header, HEADER_SIZE);
   
   secure_erase(ctx->stream, sizeof(ctx->stream));
   ctx->offset = 0;
}