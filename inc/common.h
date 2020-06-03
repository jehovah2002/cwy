#ifndef _COMMON_H_
#define _COMMON_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>


#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>



//#include <sm3hash.h>

#ifdef  __cplusplus
  extern "C" {
#endif

#define INFO_OUTPUT      3
#define WARNING_OUTPUT   2
#define DEBUG_OUTPUT     1
#define ERROR_OUTPUT     0

#define DEBUG_LEVEL     DEBUG_OUTPUT

#define INFO_PRINT(info,...)\
do{ \
if(DEBUG_LEVEL>=INFO_OUTPUT){\
    printf("Info %s,%s,%d:"info"",__FILE__,__FUNCTION__,__LINE__,##__VA_ARGS__);}\
}while(0)

#define WARNING_PRINT(info,...)\
do{ \
if(DEBUG_LEVEL>=WARNING_OUTPUT){\
    printf("Warning %s,%s,%d:"info"",__FILE__,__FUNCTION__,__LINE__,##__VA_ARGS__);}\
}while(0)

#define DEBUG_PRINT(info,...)\
do{ \
if(DEBUG_LEVEL>=DEBUG_OUTPUT){\
    printf("Debug %s,%s,%d:"info"",__FILE__,__FUNCTION__,__LINE__,##__VA_ARGS__);}\
}while(0)

#define ERROR_PRINT(info,...)\
do{ \
if(DEBUG_LEVEL>=ERROR_OUTPUT){\
    printf("Error %s,%s,%d:"info"",__FILE__,__FUNCTION__,__LINE__,##__VA_ARGS__);}\
}while(0)


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
int sm3_string_hash_string(const unsigned char *message, unsigned char *hash);



void print_HexString(unsigned char *input,unsigned int str_len,unsigned char *input_name,int DEBUGLEVEL);
void print_bn(char *pchT, BIGNUM* pBG_p,int DEBUGLEVEL);


void init_curve_param(int curve_type);
BIGNUM *k_creat(const EC_GROUP *ec_group,BN_CTX *ctx);

unsigned char *inttoAscii(unsigned int aval);

long get_CICV_current_time();
int HexToDec(char *src);


#ifdef  __cplusplus
  }
#endif

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

#define CICVHOST "36.112.19.9"
#define CICVPORT "8008"

typedef enum
{
	CICVECRSQ=0,
	CICVPCRSQ,
	CICVPCDL,
	CICVLPFDL,
	CICVLCCFDL
}CICVPATH;

#define CICVTime0 1072886400
#define CICVWeek0 1561910400
#define EachWeek 352800

#define CICVENDTIME 543553242

#define g_OBUprikey     "B561D6B08C0799911C5C58CBC4B0395461376FF19588BE5512A4B922E9765D7F"
#define g_OBUpubkx      "CD4A8CF276F4C439A9B4245D5C3332A74909AF6411900A9584F6407FA1E1F04D"
#define g_OBUpubky      "643EF9B90859BB8F26F1D5B605B65B898E6032E0863A75C95AAA0DD56C2B8D32"
#define g_LTCpubkey     "48C4339B3132305A6EB6A3B5159CE538BBA6791050FF3E23B85286D2EF5D0495809B25D06C7BB65A46B215BEDBCF1F2A9AA73A860D530F850A0A9554479EC600"
#define g_LTCprikey     "18b206360d0dbf4797ac09642b971dff5d7da19a1b35ce55198696a342776260"
#define g_LTC           "3082019430820139a00302010202083a726371e4dc4add300a06082a811ccf55018375301e310b300906035504061302434e310f300d06035504030c06555345524341301e170d3139303830383038303235395a170d3231303830373038303235395a301f310b300906035504061302434e3110300e06035504030c076c7463746573743059301306072a8648ce3d020106082a811ccf5501822d0342000448c4339b3132305a6eb6a3b5159ce538bba6791050ff3e23b85286d2ef5d0495809b25d06c7bb65a46b215bedbcf1f2a9aa73a860d530f850a0a9554479ec600a360305e301d0603551d0e0416041469c1e39da902cd6beb4ad4bf4c9f8372a768b505300c0603551d130101ff04023000301f0603551d230418301680149ddf0377fcd2a9c402a30504d70bbc26b108d88d300e0603551d0f0101ff040403020700300a06082a811ccf550183750349003046022100cc8e8cc9f5241c7f1fb6f53901fd323f9f33f2146c03ff857081af315f0a268e022100c1b81569456c9a1d53b140e17e874158832ff8d210d3ca6d03c211d0915ad4e9"
#define g_ICApubkey     "91771d107bdeaa9d249747f3146b7efbb1d5a4d256b8a32e010715fc6c125d70"

#endif

