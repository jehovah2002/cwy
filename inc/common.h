#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>
//#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
//#include <openssl/ossl_typ.h>


//#include <sm3hash.h>

#ifdef  __cplusplus
  extern "C" {
#endif

unsigned char CharToHex(unsigned char bHex);
unsigned char HexToChar(unsigned char bChar);


int AscString2HexString(unsigned char *str,unsigned int str_len,char *out);
int HexStringToAsc(const char *str,unsigned char *out);
int arrayToStr(unsigned char *buf, unsigned int buflen,unsigned char *out);
void AscStringSaveToBin(const char *filename,const char *str,unsigned int str_len);
int ReadBinToarr(const char * filename,unsigned char *buf_arr);
int base64_encode(unsigned char *str,unsigned int str_len,unsigned char *res_out);
int base64_decode(const char *code,unsigned char *res_out);


char *memcat(void *dest, unsigned int dest_len, const char *src, unsigned int src_len);
int getnum(char *instr);


int sm3_hash(const unsigned char *message, unsigned int len, unsigned char *hash, unsigned int *hash_len);
int sm3_string_hash(const unsigned char *message, unsigned int len, unsigned char *hash, unsigned int *hash_len);

void print_HexString(unsigned char *input,unsigned int str_len,unsigned char *input_name);
void print_bn(char *pchT, BIGNUM* pBG_p);


void init_curve_param(int curve_type);
BIGNUM *k_creat(const EC_GROUP *ec_group,BN_CTX *ctx);



#ifdef  __cplusplus
  }
#endif



typedef struct {
	char res[16];
	char type[128];
	char errnum[8];
	char errmsg[256];
	char length[256];
	char date[128];
	char str[4096];
}cicvserverRespond;


typedef struct {
	char method[8];
	char path[64];
	char ip[32];
	char port[8];
	char accept[16];
	char type[64];
	char length[8];
	char str[4096];
}cicvserverRequest;

typedef enum
{
	xonly=0,
	fill,
	compressy0,
	compressy1,
	uncompress
}uctype;

typedef struct sm2_sig_structure {
	unsigned char r_coordinate[32];
	unsigned char s_coordinate[32];
} SM2_SIGNATURE_STRUCT;

typedef struct sm2_key_pair_structure {
/* Private key is a octet string of 32-byte length. */
	unsigned char pri_key[32];
/* Public key is a octet string of 65 byte length. It is a 
   concatenation of 04 || X || Y. X and Y both are SM2 public 
   key coordinates of 32-byte length. */
	unsigned char pub_key[65]; 
} SM2_KEY_PAIR;


#define _P  "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF"
#define _a  "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC"
#define _b  "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93"
#define _n  "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123"
#define _Gx "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7"
#define _Gy "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"

unsigned char g_sm2_P[32];
unsigned char g_sm2_a[32];
unsigned char g_sm2_b[32];
unsigned char g_sm2_n[32];
unsigned char g_sm2_Gx[32];
unsigned char g_sm2_Gy[32];

#define g_IDA "China"


typedef enum
{
	fp256=0,
	fp192,
	f2m193,
	f2m257
}curve;

typedef int FLAG;


#ifndef HEADER_ERROR_CODES_LIST_OF_SM2_CIPHER_H
#define HEADER_ERROR_CODES_LIST_OF_SM2_CIPHER_H

#define INVALID_NULL_VALUE_INPUT    0x1000
#define INVALID_INPUT_LENGTH        0x1001
#define CREATE_SM2_KEY_PAIR_FAIL    0x1002
#define COMPUTE_SM3_DIGEST_FAIL     0x1003
#define ALLOCATION_MEMORY_FAIL      0x1004
#define COMPUTE_SM2_SIGNATURE_FAIL  0x1005
#define INVALID_SM2_SIGNATURE       0x1006
#define VERIFY_SM2_SIGNATURE_FAIL   0x1007

#endif 




