#include "iocrypt.h"


#define PASSPHRASE "test12345"

#define PATH "E:\\testfile.txt"
#define PATH_DECRYPT "E:\\testfile.txt.enc"

#define CIPHER_MODE 1 // 1 = encrypt , 0 = decrypt

int main()
{
    uint32_t mode = 0;
	uint8_t* path = NULL;
	uint32_t path_len = 0;
    iocrypt_context io;
	uint32_t r = iocrypt_init(&io, PASSPHRASE, strlen(PASSPHRASE));

#if CIPHER_MODE == 1
	mode = IOCRYPT_ENCRYPT;
	path = PATH;
#elif CIPHER_MODE == 0
    mode = IOCRYPT_DECRYPT;
	path = PATH_DECRYPT;
#endif

	path_len = strlen(path);
	r = iocrypt_crypt(&io, mode, PATH, strlen(PATH));
    getchar();
	iocrypt_free(&io);
	return 0;
}