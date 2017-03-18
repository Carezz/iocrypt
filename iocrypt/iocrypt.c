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
	uint32_t retult = 0;

	if (clen > len1 || clen > len2)
	{
		ret = IOCRYPT_ERROR;
		goto cleanup;
	}

	for (uint32_t i = 0; i < clen; i++)
	{
		retult |= (input1[i] ^ input2[i]);
	}

	if (retult != 0)
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
	uint8_t* input = NULL, *output = NULL;

	/* if we're encrypting , generate the needed keys */

	if (ctx->file.type == IOCRYPT_ENCRYPT && !iocrypt_gen_keys(&ctx->keys, ctx->iocrypt_header))
	{
		ret = IOCRYPT_ERROR;
		goto cleanup;
	}

	/* derive the hmac and header keys */

	if (mbedtls_hkdf(ctx->hash.md_info, ctx->iocrypt_header, SALT_SIZE, ctx->passphrase, ctx->passphrase_len,
		KDF_CUSTOM, sizeof(KDF_CUSTOM), ctx->keys.hmac_key, HMACKEY_SIZE) != 0)
	{
		ret = IOCRYPT_ERROR;
		goto cleanup;
	}
	
	if (mbedtls_hkdf(ctx->hash.md_info, ctx->iocrypt_header + SALT_SIZE + HASH_SIZE, SALT_SIZE, ctx->passphrase, ctx->passphrase_len,
		KDF_CUSTOM, sizeof(KDF_CUSTOM), ctx->keys.header_key, HEADER_MASTER_SIZE) != 0)
	{
		ret = IOCRYPT_ERROR;
		goto cleanup;
	}

	/* encrypt/decrypt the master subheader */

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
		ret = IOCRYPT_ERROR;
		goto cleanup;
	}

	if (mbedtls_aes_crypt_ctr(&ctx->cipher, HEADER_MASTER_SIZE, &ctx->offset, ctx->keys.header_key + CIPHERKEY_SIZE, ctx->stream, input, output) != 0)
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

	if (mbedtls_md_hmac_update(&ctx->hash, ctx->iocrypt_header + SALT_SIZE + HASH_SIZE, HEADER_SIZE - (SALT_SIZE + HASH_SIZE)) != 0)
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

	if (path_len >= MAX_PATH - 4)
	{
		ret = IOCRYPT_ERROR;
		goto cleanup;
	}

	/* Open input file */

	memcpy(file->path_name, path, path_len);

	file->in = fopen(file->path_name, INPUT_FILE_MODE);

	if (file->in == NULL)
	{
		ret = IOCRYPT_ERROR;
		goto cleanup;
	}
	// add check for decryption (remove .enc)
	memcpy(file->path_name + path_len, IOCRYPT_EXT, strlen(IOCRYPT_EXT));

	/* Obtain file length */

	if (fseek(file->in, 0, SEEK_END) != 0)
	{
		ret = IOCRYPT_ERROR;
		goto cleanup;
	}

	file->in_len = ftell(file->in);

	if (file->in_len == -1L)
	{
		ret = IOCRYPT_ERROR;
		goto cleanup;
	}

	rewind(file->in);

	file->file_blocks = file->in_len / FILE_BUF_SIZE;
	file->final_block = file->in_len % FILE_BUF_SIZE;

	/* Create output file */

	file->out = fopen(file->path_name, OUTPUT_FILE_MODE);

	if (file->out == NULL)
	{
		ret = IOCRYPT_ERROR;
		goto cleanup;
	}

	if (fwrite(NULL, 1, HEADER_SIZE, file->out) != HEADER_SIZE)
	{
		ret = IOCRYPT_ERROR;
		goto cleanup;
	}

cleanup:
	return ret;
}

static uint32_t iocrypt_file_crypt(iocrypt_context* ctx, uint32_t buf_len)
{
	uint32_t ret = IOCRYPT_SUCCESS;

	if (fread(ctx->file.file_buf, 1, buf_len, ctx->file.in) != buf_len)
	{ 
		ret = IOCRYPT_ERROR;
		goto cleanup;
	}

	if (mbedtls_aes_crypt_ctr(&ctx->cipher, buf_len, &ctx->offset, ctx->keys.master_key + IV_SIZE, ctx->stream,
		ctx->file.file_buf, ctx->file.file_buf) != 0)
	{
		ret = IOCRYPT_ERROR;
		goto cleanup;
	}

	if (mbedtls_md_hmac_update(&ctx->hash, ctx->file.file_buf, buf_len) != 0)
	{
		ret = IOCRYPT_ERROR;
		goto cleanup;
	}


	if (fwrite(ctx->file.file_buf, 1, buf_len, ctx->file.out) != buf_len)
	{
		ret = IOCRYPT_ERROR;
		goto cleanup;
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

	uint32_t ret = IOCRYPT_SUCCESS;
	uint8_t* hmac_ptr = ctx->iocrypt_header + SALT_SIZE;
	uint8_t hmac[HASH_SIZE] = {0};

	ctx->file.type = type;

	if (!iocrypt_file_init(&ctx->file, file_path, file_path_len))
	{
		ret = IOCRYPT_ERROR;
		goto cleanup;
	}

	if (type == IOCRYPT_DECRYPT)
	{
	  if(fread(ctx->iocrypt_header, 1, HEADER_SIZE, ctx->file.in) != HEADER_SIZE)
	  { 
		ret = IOCRYPT_ERROR;
		goto cleanup;
	  }

	  hmac_ptr = hmac;
	}

	if (!iocrypt_derive_keys(ctx))
	{
		ret = IOCRYPT_ERROR;
		goto cleanup;
	}

	while (ctx->file.file_blocks--)
	{
		if (!iocrypt_file_crypt(ctx, FILE_BUF_SIZE))
		{
			ret = IOCRYPT_ERROR;
			goto cleanup;
		}
	}

	if (ctx->file.final_block && !iocrypt_file_crypt(ctx, ctx->file.final_block))
	{
		ret = IOCRYPT_ERROR;
		goto cleanup;
	}

	if (mbedtls_md_hmac_finish(&ctx->hash, hmac_ptr) != 0)
	{
		ret = IOCRYPT_ERROR;
		goto cleanup;
	}

	rewind(ctx->file.out);

	if (ctx->file.type == IOCRYPT_ENCRYPT)
	{ 
	   if(fwrite(ctx->iocrypt_header, 1, HEADER_SIZE, ctx->file.out) != HEADER_SIZE)
	   {
		   ret = IOCRYPT_ERROR;
		   goto cleanup;
	   }
	}
	else
	{
	   if(!iocrypt_timesafe_compare(hmac, HASH_SIZE, ctx->iocrypt_header + SALT_SIZE, HASH_SIZE, HASH_SIZE))
	   {
		   ret = IOCRYPT_ERROR;
		   goto cleanup;
	   }
	}

cleanup:
    if(!ret) remove(ctx->file.path_name); // unsure about this...
	hmac_ptr = NULL;
	iocrypt_secure_erase(hmac, HASH_SIZE);
    iocrypt_file_free(&ctx->file);
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
   iocrypt_secure_erase(&ctx->iocrypt_header, HEADER_SIZE);
   
   iocrypt_secure_erase(ctx->stream, sizeof(ctx->stream));
   ctx->offset = 0;
}