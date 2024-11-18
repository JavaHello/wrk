#ifndef __SHA_WITH_RSA
#define __SHA_WITH_RSA

int rsa_add_private_key(const int idx, const char *private_key_path);
void rsa_clear_all_private_key();
char *sha256_with_rsa_base64(const char *message, int private_key_index);
char *sha512_with_rsa_base64(const char *message, int private_key_index);

#endif /* ifdef RSA_SHA256 */
