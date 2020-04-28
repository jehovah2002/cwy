#ifdef  __cplusplus
  extern "C" {
#endif

char *memcat(void *dest, unsigned int dest_len, const char *src, unsigned int src_len);
int getnum(char *instr);


int jointPostPkg(const char *IPSTR,const char *PORT,unsigned const char *str,int str_len,char *res_out);
int SendbyPost(const char *IPSTR,const char *PORT,unsigned const char *str,int str_len,unsigned char *res);
int splitRecvPkg(unsigned char instr[]);
void respondSave(char *instr,int flag);
void printrespond();


#ifdef  __cplusplus
  }
#endif









