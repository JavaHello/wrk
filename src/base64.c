
#include "base64.h"
#include "zmalloc.h"
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <string.h>

char *base64_encode(unsigned char *sign, int sign_len) {
  if (sign == NULL) {
    return NULL;
  }
  BIO *b64 = BIO_new(BIO_f_base64());
  BIO *bio = BIO_new(BIO_s_mem());
  bio = BIO_push(b64, bio);
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  BIO_write(bio, sign, sign_len);
  BIO_flush(bio);
  BUF_MEM *bptr = NULL;
  BIO_get_mem_ptr(bio, &bptr);
  char *buff = (char *)zmalloc(bptr->length + 1);
  if (buff == NULL) {
    perror("Memory allocation failed");
    return NULL;
  }
  memcpy(buff, bptr->data, bptr->length);
  buff[bptr->length] = '\0';

  BIO_free_all(b64);
  return buff;
}

unsigned char *base64_decode(const char *encoded_data) {
  if (encoded_data == NULL) {
    return NULL;
  }
  BIO *bio, *b64;
  size_t length = strlen(encoded_data);

  b64 = BIO_new(BIO_f_base64());
  bio = BIO_new_mem_buf(encoded_data, length);
  bio = BIO_push(b64, bio);
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

  unsigned char *decoded_data = (unsigned char *)zmalloc(length);
  if (decoded_data == NULL) {
    perror("Memory allocation failed");
    return NULL;
  }

  size_t size = BIO_read(bio, decoded_data, length);
  if (size < 0) {
    perror("Base64 decoding failed");
    return NULL;
  }
  decoded_data[size] = '\0';

  BIO_free_all(b64);
  return decoded_data;
}
