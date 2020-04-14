#include "autoc.h"


 
int sm3_hash(const unsigned char *message, unsigned int len, unsigned char *hash, unsigned int *hash_len)
{
    EVP_MD_CTX *md_ctx;
    const EVP_MD *md;
    md = EVP_sm3();
    md_ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(md_ctx, md, NULL);
    EVP_DigestUpdate(md_ctx, message, len);
    EVP_DigestFinal_ex(md_ctx, hash, hash_len);
    EVP_MD_CTX_free(md_ctx);
    return 0;
}

int sm3_string_hash(const unsigned char *message, unsigned int len, unsigned char *hash, unsigned int *hash_len)
{
	int buf_len=0;
	unsigned char buf_arr[4096]={0};
    buf_len=HexStringToAsc(message,(char *)buf_arr);
	sm3_hash(buf_arr,buf_len,hash,hash_len);
    return 0;
}


