#ifndef _AUTOC_H_
#define _AUTOC_H_

#include "common.h"
#include "autoasn.h"
#include "network.h"
#include "sm2_sign_and_verify.h"


#ifdef  __cplusplus
  extern "C" {
#endif

int Auto_ECA(const char *Subjectname,const char *LTCprikey,const char *LTCpubkey,const char *OBUpubkx,const char *OBUpubky,const char *LTCStr);
int ECA_EC_Verify(CicvserverRespond_t *serverRespond);


#ifdef  __cplusplus
  }
#endif

#endif







