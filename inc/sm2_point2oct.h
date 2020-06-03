#ifndef _SM2_POINT2OCT_H_
#define _SM2_POINT2OCT_H_

#include <sys/ipc.h>
#include <sys/shm.h>
#include "common.h"


#ifdef  __cplusplus
  extern "C" {
#endif

void sm2_point2oct (unsigned char ucType, unsigned char* pucInX, unsigned char* pucOutXY );
int untar_x_to_y(const int ucType, const char* pucInX, unsigned char* pucOutXY);


#define MAX_PKCACHE_NUM 128
  
  typedef struct {
      unsigned long long nXValue;
      unsigned char pk[64];
  } TUncompressedPKItem;
  
  typedef struct {
      int index;
      TUncompressedPKItem uncompressPK[MAX_PKCACHE_NUM]; 
  } TUncompressedShm;

int BN_bn2bin_ex(BIGNUM *bn, unsigned char *to, int len);
EC_GROUP* SM2Group();
int UncompressCacheGet(unsigned long long xdata, unsigned char* pk);
int UncompressPKCachePut(unsigned long long xdata, unsigned char* pk);
int CryptoUncompressPK(int cacheFlag, unsigned char* compressed, int len, unsigned char *pk);
int MizarInitShm(int key, int size);
void *MizarAttachShm(int shmid);



#ifdef  __cplusplus
  }
#endif


#endif






