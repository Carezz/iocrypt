#include "iocrypt.h"

/* crypto */

static void iocrypt_secure_erase(void* data, uint64_t len)
{
   if(data == NULL || len == 0) return;

   volatile unsigned char* p = (volatile unsigned char*)data;
   while(len--) *p++ = 0;
}

static uint32_t iocrypt_timesafe_compare(uint8_t* input1, uint32_t len1, uint8_t* input2, uint32_t len2, uint32_t clen)
{
	uint32_t ret = IOCRYPT_SUCCESS;
	uint32_t result = 0;

	if (clen > len1 || clen > len2)
	{
		ret = IOCRYPT_ERROR;
		goto cleanup;
	}

	for (uint32_t i = 0; i < clen; i++)
	{
		result |= (input1[i] ^ input2[i]);
	}

	if (result != 0)
	{
		ret = IOCRYPT_ERROR;
		goto cleanup;
	}

cleanup:
	return ret;
}

static uint32_t iocrypt_gen_keys(iocrypt_keys_context* keys, uint8_t* iocrypt_header)
{
    uint32_t ret = IOCRYPT_SUCCESS;
	mbedtls_entropy_context entropy;
	mbedtls_entropy_init(&entropy);

	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ctr_drbg_init(&ctr_drbg);

	if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, PRNG_CUSTOM, sizeof(PRNG_CUSTOM)) != 0)
	{
	   ret = IOCRYPT_ERROR;
	   goto cleanup;
	}

	if (mbedtls_ctr_drbg_random(&ctr_drbg, keys->master_key, HEADER_MASTER_SIZE) != 0)
	{
	   ret = IOCRYPT_ERROR;
	   goto cleanup;
	}

	if (mbedtls_ctr_drbg_random(&ctr_drbg, iocrypt_header, SALT_SIZE) != 0)
	{
		ret = IOCRYPT_ERROR;
		goto cleanup;
	}

	if (mbedtls_ctr_drbg_random(&ctr_drbg, iocrypt_header + SALT_SIZE + HASH_SIZE, SALT_SIZE) != 0)
	{
		ret = IOCRYPT_ERROR;
		goto cleanup;
	}

cleanup:
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	return ret;
}

static uint32_t iocrypt_derive_keys(iocrypt_context* ctx)
{
	uint32_t ret = IOCRYPT_SUCCESS;
	uint8_t* input = ctx->keys.master_key, *output = ctx->file.iocrypt_header + SALT_SIZE + HASH_SIZE + SALT_SIZE;

	/* if we're encrypting , generate the needed keys */

	if (ctx->file.type == IOCRYPT_ENCRYPT && !iocrypt_gen_keys(&ctx->keys, ctx->file.iocrypt_header))
	{
		ret = IOCRYPT_ERROR;
		goto cleanup;
	}

	/* derive the hmac and header keys */

	if (mbedtls_hkdf(ctx->hash.md_info, ctx->file.iocrypt_header, SALT_SIZE, ctx->passphrase, ctx->passphrase_len,
		KDF_CUSTOM, sizeof(KDF_CUSTOM), ctx->keys.hmac_key, HMACKEY_SIZE) != 0)
	{
		ret = IOCRYPT_ERROR;
		goto cleanup;
	}
	
	if (mbedtls_hkdf(ctx->hash.md_info, ctx->file.iocrypt_header + SALT_SIZE + HASH_SIZE, SALT_SIZE, ctx->passphrase, ctx->passphrase_len,
		KDF_CUSTOM, sizeof(KDF_CUSTOM), ctx->keys.header_key, HEADER_MASTER_SIZE) != 0)
	{
		ret = IOCRYPT_ERROR;
		goto cleanup;
	}

	/* encrypt/decrypt the master subheader */

	if (ctx->file.type == IOCRYPT_DECRYPT)
	{
		uint8_t* tmp = input;
		input = output;
		output = tmp;
	}

	if (mbedtls_aes_setkey_enc(&ctx->cipher, ctx->keys.header_key, CIPHERKEY_BITS) != 0)
	{
		ret = IOCRYPT_ERROR;
		goto cleanup;
	}

	if (mbedtls_aes_crypt_ctr(&ctx->cipher, HEADER_MASTER_SIZE, &ctx->offset, ctx->keys.header_iv, ctx->stream, input, output) != 0)
	{
		ret = IOCRYPT_ERROR;
		goto cleanup;
	}

	mbedtls_aes_free(&ctx->cipher);

	/* set up the master key & HMAC key*/

	if (mbedtls_aes_setkey_enc(&ctx->cipher, ctx->keys.master_key, CIPHERKEY_BITS) != 0)
	{
		ret = IOCRYPT_ERROR;
		goto cleanup;
	}

	if (mbedtls_md_hmac_starts(&ctx->hash, ctx->keys.hmac_key, HMACKEY_SIZE) != 0)
	{
		ret = IOCRYPT_ERROR;
		goto cleanup;
	}

	if (mbedtls_md_hmac_update(&ctx->hash, ctx->file.iocrypt_header + SALT_SIZE + HASH_SIZE, HEADER_SIZE - (SALT_SIZE + HASH_SIZE)) != 0)
	{
		ret = IOCRYPT_ERROR;
		goto cleanup;
	}

cleanup:
	input = NULL;
	output = NULL;
	return ret;
}

/* file */

static uint32_t iocrypt_file_init(iocrypt_file_context* file, uint8_t* path, uint32_t path_len)
{
	uint32_t ret = IOCRYPT_SUCCESS;

	if (path_len > MAX_PATH - (file->type*5))
	{
		ret = IOCRYPT_ERROR;
		goto cleanup;
	}

	/* Open input file */

	memcpy(file->path, path, path_len);

	file->in = fopen(file->path, INPUT_FILE_MODE);

	if (file->in == NULL)
	{
		ret = IOCRYPT_ERROR;
		goto cleanup;
	}

	if(file->type == IOCRYPT_ENCRYPT)
	{ 
	   memcpy(file->path + path_len, IOCRYPT_EXT, strlen(IOCRYPT_EXT));
	}
	else
	{ // (works but insecure)
	   uint8_t* p = &file->path[path_len-1];
	   while(*--p != '.');
	   memset(p, 0, strlen(IOCRYPT_EXT));
	}

	/* Create output file */

	file->out = fopen(file->path, OUTPUT_FILE_MODE);

	if (file->out == NULL)
	{
		ret = IOCRYPT_ERROR;
		goto cleanup;
	}

	/* pad the header upon encryption or read the header upon decryption */

	if (file->type == IOCRYPT_ENCRYPT)
	{
		if(fwrite(file->file_buf, 1, HEADER_SIZE, file->out) != HEADER_SIZE)
		{
			ret = IOCRYPT_ERROR;
			goto cleanup;
		}
	}
	else
	{
		if (fread(file->iocrypt_header, 1, HEADER_SIZE, file->in) != HEADER_SIZE)
		{
			ret = IOCRYPT_ERROR;
			goto cleanup;
		}
	}

cleanup:
	return ret;
}

static void iocrypt_file_free(iocrypt_file_context* file)
{
	if (file->in)
		fclose(file->in);

	if (file->out)
		fclose(file->out);

	iocrypt_secure_erase(file, sizeof(iocrypt_file_context));
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
	memset(ctx->file.iocrypt_header, 0, HEADER_SIZE);

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

	uint32_t ret = IOCRYPT_SUCCESS;
	uint8_t* hmac_ptr = ctx->file.iocrypt_header + SALT_SIZE;
	uint8_t hmac[HASH_SIZE] = {0};

	ctx->file.type = type;

	if (!iocrypt_file_init(&ctx->file, file_path, file_path_len))
	{
		ret = IOCRYPT_ERROR;
		goto cleanup;
	}

	if (!iocrypt_derive_keys(ctx))
	{
		ret = IOCRYPT_ERROR;
		goto cleanup;
	}

	while ((ctx->file.len = fread(ctx->file.file_buf, 1, FILE_BUF_SIZE, ctx->file.in)) > 0)
	{
		if (mbedtls_aes_crypt_ctr(&ctx->cipher, ctx->file.len, &ctx->offset, ctx->keys.master_iv, 
		                           ctx->stream, ctx->file.file_buf, ctx->file.file_buf) != 0)
		{
			ret = IOCRYPT_ERROR;
			goto cleanup;
		}

		if (mbedtls_md_hmac_update(&ctx->hash, ctx->file.file_buf, ctx->file.len) != 0)
		{
			ret = IOCRYPT_ERROR;
			goto cleanup;
		}

		if(fwrite(ctx->file.file_buf, 1, ctx->file.len, ctx->file.out) != ctx->file.len)
		{
			ret = IOCRYPT_ERROR;
			goto cleanup;
		}
	}

	if (type == IOCRYPT_DECRYPT)
		hmac_ptr = hmac;

	if (mbedtls_md_hmac_finish(&ctx->hash, hmac_ptr) != 0)
	{
		ret = IOCRYPT_ERROR;
		goto cleanup;
	}

	if (ctx->file.type == IOCRYPT_ENCRYPT)
	{ 
	   rewind(ctx->file.out);

	   if(fwrite(ctx->file.iocrypt_header, 1, HEADER_SIZE, ctx->file.out) != HEADER_SIZE)
	   {
		   ret = IOCRYPT_ERROR;
		   goto cleanup;
	   }
	}
	else
	{
	   if(iocrypt_timesafe_compare(hmac, HASH_SIZE, ctx->file.iocrypt_header + SALT_SIZE, HASH_SIZE, HASH_SIZE) != 0)
	   {
		   ret = IOCRYPT_ERROR;
		   goto cleanup;
	   }
	}

cleanup:
	hmac_ptr = NULL;
	ctx->offset = 0;
	iocrypt_secure_erase(ctx->stream, sizeof(ctx->stream));
	iocrypt_secure_erase(hmac, HASH_SIZE);
	iocrypt_secure_erase(&ctx->keys, sizeof(iocrypt_keys_context));
    iocrypt_file_free(&ctx->file);
	mbedtls_md_free(&ctx->hash);
	mbedtls_aes_free(&ctx->cipher);
	return ret;
}

void iocrypt_free(iocrypt_context* ctx)
{
   if(ctx == NULL) return;

   iocrypt_secure_erase(&ctx->file, sizeof(iocrypt_file_context));
   ctx->passphrase = NULL;
   ctx->passphrase_len = 0;
   mbedtls_md_free(&ctx->hash);
   mbedtls_aes_free(&ctx->cipher);
   iocrypt_secure_erase(&ctx->keys, sizeof(iocrypt_keys_context));
   iocrypt_secure_erase(&ctx->file.iocrypt_header, HEADER_SIZE);
   
   iocrypt_secure_erase(ctx->stream, sizeof(ctx->stream));
   ctx->offset = 0;
}