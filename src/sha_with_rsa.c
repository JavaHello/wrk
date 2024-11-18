#include "sha_with_rsa.h"
#include "base64.h"
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <string.h>

// 私钥数量
#define PRIVATE_KEY_COUNT 32

RSA *rsa_private_key[PRIVATE_KEY_COUNT];

int rsa_add_private_key(const int idx, const char *private_key_path) {
  if (idx > -1 && idx < PRIVATE_KEY_COUNT) {
    if (rsa_private_key[idx] != NULL) {
      RSA_free(rsa_private_key[idx]);
    }
    FILE *fp = fopen(private_key_path, "r");
    rsa_private_key[idx] = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    return idx;
  }
  return -1;
}

void rsa_clear_all_private_key() {
  for (int i = 0; i < PRIVATE_KEY_COUNT; i++) {
    if (rsa_private_key[i] != NULL) {
      RSA_free(rsa_private_key[i]);
      rsa_private_key[i] = NULL;
    }
  }
}

char *SHA256_With_RSA(const char *message, int private_key_index,
                      char *(*signfn)(unsigned char *, int)) {
  RSA *rsa = rsa_private_key[private_key_index];

  if (rsa == NULL) {
    printf("private key not found\n");
    exit(1);
  }

  // 创建SHA256摘要
  unsigned char digest[SHA256_DIGEST_LENGTH];
  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, message, strlen(message));
  SHA256_Final(digest, &sha256);

  // 生成签名
  unsigned char sig[256];
  unsigned int sig_len;
  if (RSA_sign(NID_sha256, digest, SHA256_DIGEST_LENGTH, sig, &sig_len, rsa) !=
      1) {
    printf("sign error\n");
    return NULL;
  }
  return signfn(sig, sig_len);
}
char *sha256_with_rsa_base64(const char *message, int private_key_index) {
  return SHA256_With_RSA(message, private_key_index, base64_encode);
}
