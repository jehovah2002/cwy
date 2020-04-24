#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>

#include <openssl/bn.h>
#include <openssl/evp.h>
//#include <sm3hash.h>


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


int jointPostPkg(const char *IPSTR,const char *PORT,unsigned const char *str,int str_len,char *res_out);
int SendbyPost(const char *IPSTR,const char *PORT,unsigned const char *str,int str_len,unsigned char *res);
int splitRecvPkg(unsigned char instr[]);
void respondSave(char *instr,int flag);
void printrespond();

int sm3_hash(const unsigned char *message, unsigned int len, unsigned char *hash, unsigned int *hash_len);
int sm3_string_hash(const unsigned char *message, unsigned int len, unsigned char *hash, unsigned int *hash_len);

void sm2_point2oct (unsigned char ucType, unsigned char* pucInX, unsigned char* pucOutXY );
int untar_x_to_y(const char* ucType, const char* pucInX, unsigned char* pucOutXY);





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


#define _P  "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF"
#define _a  "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC"
#define _b  "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93"
#define _n  "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123"
#define _Gx "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7"
#define _Gy "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"






