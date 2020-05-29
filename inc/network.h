#ifndef _NETWORK_H_
#define _NETWORK_H_

#ifdef  __cplusplus
  extern "C" {
#endif

typedef struct CicvserverRespond{
	char res[16];
	char type[128];
	char errnum[8];
	char errmsg[256];
	char length[256];
	char date[128];
	char str[4096];
}CicvserverRespond_t;

typedef struct CicvserverRequest{
	char method[8];
	char path[64];
	char ip[32];
	char port[8];
	char accept[16];
	char type[64];
	char length[8];
	char str[4096];
}CicvserverRequest_t;


//int jointPostPkg(const char *IPSTR,const char *PORT,unsigned const char *str,int str_len,char *res_out);
int jointPostPkg(const char *sendtype,const char *path,const char *IPSTR,const char *PORT,unsigned const char *str,int str_len,char *res_out);

//int SendbyPost(const char *IPSTR,const char *PORT,unsigned const char *str,int str_len,unsigned char *res);
int SendbyPost(const char *sendtype,const char *path,const char *IPSTR,const char *PORT,unsigned const char *str,int str_len,unsigned char *res);

int splitRecvPkg(unsigned char *instr,CicvserverRespond_t *serverRespond);

//int splitRecvPkg(unsigned char instr[]);
void respondSave(char *instr,int flag,CicvserverRespond_t *serverRespond);
void printrespond(CicvserverRespond_t *serverRespond);




//cicvserverRequest_t serverRequest={0};
//cicvserverRespond_t serverRespond={0};


#ifdef  __cplusplus
  }
#endif


#endif






