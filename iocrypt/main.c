#include "iocrypt.h"

int main()
{
    iocrypt_context io;
	uint32_t r = iocrypt_init(&io, "test12345", sizeof("test12345"));
	
	r = iocrypt_crypt(&io, IOCRYPT_ENCRYPT, 0, "test.txt", 0);

    getchar();
	iocrypt_free(&io);
	return 0;
}