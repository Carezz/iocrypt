#include "iocrypt.h"

int main()
{
    iocrypt_context io;
	uint32_t r = iocrypt_init(&io, "test12345", sizeof("test12345") - 1);

	printf("%d", r);
	
	r = iocrypt_crypt(&io, IOCRYPT_ENCRYPT, 0, "test.txt", sizeof("test.txt"));

	printf("%d", r);

    getchar();
	iocrypt_free(&io);
	return 0;
}