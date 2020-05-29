#ifndef _SM2_CRYPTO_H_
#define _SM2_CRYPTO_H_

#ifdef  __cplusplus
  extern "C" {
#endif

unsigned long sm2Encrypt(unsigned char *x,
                                unsigned char *y,
                                unsigned char *encryptData,
                                unsigned long encryptDataLen,
                                unsigned char *outData);


//void *kdf(const EVP_MD *md, const void *in, size_t inlen,
//          void *out, size_t *outlen);

int my_KDF(const char* cdata, int datalen, int keylen, char* retdata);

unsigned long sm2Encrypt_Ex(const int keytype,
                                    const unsigned char *pub_key,
                                    unsigned char *encryptData,
                                    unsigned long encryptDataLen,
                                    unsigned char *outData);

unsigned long sm2Decrypt(unsigned char *prikey,
                                unsigned char *decryptData,
                                unsigned long decryptDataLen,
                                unsigned char *outData);

unsigned long sm2Decrypt_Ex(unsigned char *prikey,
                                    unsigned char prikeyLen,
                                    unsigned char *decryptData,
                                    unsigned char decryptDataLen,
                                    unsigned char *outData);




#define POINT_BIN_LENGTH 65


#ifdef  __cplusplus
  }
#endif

#endif

