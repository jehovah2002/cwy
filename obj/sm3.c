#include "common.h"
#include "sm3.h"
#include "sm2_sign_and_verify.h"


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

int sm3_string_hash_string(const unsigned char *message, unsigned char *hash)
{
	int buf_len=0;
    int ret=0;
    int str_len=0;
	unsigned char buf_in[4096]={0};
    unsigned char buf_out[128]={0};

    buf_len=HexStringToAsc(message,buf_in);
    INFO_PRINT("message =[%s]\n",message);
    //ERROR_PRINT("buf_len =[%d]\n",buf_len);
	sm3_hash(buf_in,buf_len,buf_out,&str_len);
    INFO_PRINT("str_len = [%d],buf_len =[%d]\n",str_len,buf_len);
    if(32!=str_len)
    {
        ERROR_PRINT("hash length error .[%d]",str_len);
        return -1;
    }
    ret=AscString2HexString(buf_out,str_len,hash);
	//arrayToStr(argv[2],strlen(argv[2]),outstr);
    return ret;
}



/*********************************************************/
int sm3_digest_z(const unsigned char *id,
						const int id_len,
						const unsigned char *pub_key,
						unsigned char *z_digest)
{
	int id_bit_len = id_len * 8;
	unsigned char entl[2];
	/*
	unsigned char sm2_param_a[32] = {0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff,
	                                 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
					 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
					 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc};
	unsigned char sm2_param_b[32] = {0x28, 0xe9, 0xfa, 0x9e, 0x9d, 0x9f, 0x5e, 0x34,
		                         0x4d, 0x5a, 0x9e, 0x4b, 0xcf, 0x65, 0x09, 0xa7,
					 0xf3, 0x97, 0x89, 0xf5, 0x15, 0xab, 0x8f, 0x92,
					 0xdd, 0xbc, 0xbd, 0x41, 0x4d, 0x94, 0x0e, 0x93};
	unsigned char sm2_param_x_G[32] = {0x32, 0xc4, 0xae, 0x2c, 0x1f, 0x19, 0x81, 0x19,
		                           0x5f, 0x99, 0x04, 0x46, 0x6a, 0x39, 0xc9, 0x94,
					   0x8f, 0xe3, 0x0b, 0xbf, 0xf2, 0x66, 0x0b, 0xe1,
					   0x71, 0x5a, 0x45, 0x89, 0x33, 0x4c, 0x74, 0xc7};
	unsigned char sm2_param_y_G[32] = {0xbc, 0x37, 0x36, 0xa2, 0xf4, 0xf6, 0x77, 0x9c,
		                           0x59, 0xbd, 0xce, 0xe3, 0x6b, 0x69, 0x21, 0x53,
					   0xd0, 0xa9, 0x87, 0x7c, 0xc6, 0x2a, 0x47, 0x40,
					   0x02, 0xdf, 0x32, 0xe5, 0x21, 0x39, 0xf0, 0xa0};
	*/
	unsigned char x_coordinate[32];
	unsigned char y_coordinate[32];
	EVP_MD_CTX *md_ctx;
    const EVP_MD *md;
	
	if ( !(id) || !(pub_key) || !(z_digest) )
	{
	   return INVALID_NULL_VALUE_INPUT;
	}

	if ( (id_bit_len <= 0) || (id_bit_len > 65535) )
	{
	   return INVALID_INPUT_LENGTH;
	}
	
	entl[0] = (id_bit_len & 0xff00) >> 8;
	entl[1] = id_bit_len & 0xff;
	DEBUG_PRINT("entl[0]=[%02X],entl[1]=[%02X],id_bit_len=[%d]\n",entl[0],entl[1],id_bit_len);
	memcpy(x_coordinate, (pub_key + 1), sizeof(x_coordinate));
	memcpy(y_coordinate, (pub_key + 1 + sizeof(x_coordinate)), sizeof(y_coordinate));
	
	md = EVP_sm3();
    if ( !(md_ctx = EVP_MD_CTX_new()) )
	{
       ERROR_PRINT("Allocate a digest context failed !\n");
	   return COMPUTE_SM3_DIGEST_FAIL;
	}
    EVP_DigestInit_ex(md_ctx, md, NULL);
    EVP_DigestUpdate(md_ctx, entl, sizeof(entl));
	//printf("entl=[%s]\n",entl);
	EVP_DigestUpdate(md_ctx, id, id_len);
	EVP_DigestUpdate(md_ctx, g_sm2_a, sizeof(g_sm2_a));
	EVP_DigestUpdate(md_ctx, g_sm2_b, sizeof(g_sm2_b));
	EVP_DigestUpdate(md_ctx, g_sm2_Gx, sizeof(g_sm2_Gx));
	EVP_DigestUpdate(md_ctx, g_sm2_Gy, sizeof(g_sm2_Gy));
	EVP_DigestUpdate(md_ctx, x_coordinate, sizeof(x_coordinate));
	EVP_DigestUpdate(md_ctx, y_coordinate, sizeof(y_coordinate));

    EVP_DigestFinal_ex(md_ctx, z_digest, NULL);
	print_HexString(x_coordinate,32,"x_coordinate",DEBUG_OUTPUT);
	print_HexString(y_coordinate,32,"y_coordinate",DEBUG_OUTPUT);
	//print_HexString(z_digest,32,"z_digest");
    EVP_MD_CTX_free(md_ctx);
	return 0;
}

/*********************************************************/
int sm3_digest_with_preprocess(const unsigned char *message,
                                            const int message_len,
                                            const unsigned char *id,
                                            const int id_len,
                                            const unsigned char *pub_key,
                                            unsigned char *digest)
    {
    int error_code;
    unsigned char z_digest[32];
    EVP_MD_CTX *md_ctx;
    const EVP_MD *md;

    if ( error_code = sm3_digest_z(id,
                                    id_len,
                                    pub_key,
                                    z_digest) )
    {
        ERROR_PRINT("Compute SM3 digest of leading data Z failed at %s, line %d!\n", __FILE__, __LINE__);
        return COMPUTE_SM3_DIGEST_FAIL;	
    }

    md = EVP_sm3();
    if ( !(md_ctx = EVP_MD_CTX_new()) )
    {
        ERROR_PRINT("Allocate a digest context failed at %s, line %d!\n", __FILE__, __LINE__);
        return COMPUTE_SM3_DIGEST_FAIL;
    }
    EVP_DigestInit_ex(md_ctx, md, NULL);
    EVP_DigestUpdate(md_ctx, z_digest, sizeof(z_digest));
    EVP_DigestUpdate(md_ctx, message, message_len);
    EVP_DigestFinal_ex(md_ctx, digest, NULL);
    EVP_MD_CTX_free(md_ctx);
    return 0;
}


