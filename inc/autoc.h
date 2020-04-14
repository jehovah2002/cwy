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




int HexStringToHex(const char *str,char *out);
int arrayToStr(unsigned char *buf, unsigned int buflen,unsigned char *out);
void StringSaveToBin(const char *filename,const char *str,unsigned int str_len);
int ReadBinToarr(const char * filename,unsigned char *buf_arr);
unsigned char *base64_encode(unsigned char *str);
int base64_decode(const char *code,unsigned char *res_out);  //need free
char *memcat(void *dest, size_t dest_len, const char *src, size_t src_len);

int jointPostPkg(const char *IPSTR,const char *PORT,unsigned const char *str,int str_len,char *res_out);
int SendbyPost(const char *IPSTR,const char *PORT,unsigned const char *str,int str_len,unsigned char *res);


int splitRecvPkg(unsigned char instr[]);
void respondSave(char *instr,int flag);
void printrespond();

int sm3_hash(const unsigned char *message, size_t len, unsigned char *hash, unsigned int *hash_len);
int sm3_string_hash(const unsigned char *message, size_t len, unsigned char *hash, unsigned int *hash_len);



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





