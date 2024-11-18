#ifndef __BASE64
#define __BASE64

#include "zmalloc.h"
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <string.h>

char *base64_encode(unsigned char *sign, int sign_len) {
  if (sign == NULL) {
    return NULL;
  }
  BIO *b64 = BIO_new(BIO_f_base64());
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  BIO *bio = BIO_new(BIO_s_mem());
  bio = BIO_push(b64, bio);
  BIO_write(bio, sign, sign_len);
  BIO_flush(bio);
  BUF_MEM *bptr = NULL;
  BIO_get_mem_ptr(bio, &bptr);
  char *buff = (char *)zmalloc(bptr->length);
  if (buff == NULL) {
    perror("Memory allocation failed");
    return NULL;
  }
  memcpy(buff, bptr->data, bptr->length - 1);
  buff[bptr->length - 1] = 0;
  BIO_free_all(bio);
  return buff;
}

unsigned char *base64_decode(const char *encoded_data) {
  if (encoded_data == NULL) {
    return NULL;
  }
  BIO *bio, *b64;
  size_t length = strlen(encoded_data);

  // 创建一个BIO对象链，包括Base64解码器和内存缓冲区
  b64 = BIO_new(BIO_f_base64());
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  bio = BIO_new_mem_buf(encoded_data, length);
  bio = BIO_push(b64, bio);

  // 计算解码后的数据长度
  unsigned char *decoded_data = (unsigned char *)zmalloc(length);
  if (decoded_data == NULL) {
    perror("Memory allocation failed");
    return NULL;
  }

  // 执行Base64解码
  size_t size = BIO_read(bio, decoded_data, length);
  if (size < 0) {
    perror("Base64 decoding failed");
    return NULL;
  }
  decoded_data[size] = '\0';

  // 释放资源
  BIO_free_all(bio);

  return decoded_data;
}

#endif
