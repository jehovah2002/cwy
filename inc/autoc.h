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



int HexStringToHex(const char *str,char *out);
int arrayToStr(unsigned char *buf, unsigned int buflen,unsigned char *out);
void StringSaveToBin(const char *filename,const char *str,unsigned int str_len);
int ReadBinToarr(const char * filename,unsigned char *buf_arr);
unsigned char *base64_encode(unsigned char *str);
int base64_decode(const char *code,unsigned char *res_out);  //need free
char *memcat(void *dest, size_t dest_len, const char *src, size_t src_len);
int jointPostPkg(const char *IPSTR,const char *PORT,unsigned const char *str,int str_len,char *res_out);
int SendbyPost(const char *IPSTR,const char *PORT,unsigned const char *str,int str_len,unsigned char *res);
int splitRecvPkg(unsigned char *instr,char outstr[]);
void Useage();

