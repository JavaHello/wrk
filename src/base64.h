#ifndef __BASE64
#define __BASE64

#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <string.h>

char *base64_encode(unsigned char *sign, int sign_len);
unsigned char *base64_decode(const char *encoded_data);
#endif
