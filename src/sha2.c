#include "sha2.h"
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <string.h>

void bin_to_hex(const unsigned char *bin, size_t bin_len, char *hex) {
  for (size_t i = 0; i < bin_len; i++) {
    sprintf(hex + (i * 2), "%02x", bin[i]);
  }
}

void sha256(const char *message, char *hex) {

  // 创建SHA256摘要
  unsigned char digest[SHA256_DIGEST_LENGTH];
  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, message, strlen(message));
  SHA256_Final(digest, &sha256);
  bin_to_hex(digest, SHA256_DIGEST_LENGTH, hex);
}
