#include "autoc.h"
#include "common.h"
#include "autoasn.h"
#include "network.h"

int Auto_ECA(const char *Subjectname,const char *LTCprikey,const char *LTCpubkey,const char *OBUpubkx,const char *OBUpubky,const char *LTCStr)
{
    char ECAStr[4096]={0};
    char asn_arr[4096]={0};
    char outstr[4096]={0};
    int str_len=0;
    int ret=0;
    CicvserverRespond_t serverRespond;

    CreatCicvECSecuredMessage(Subjectname,
                            CICVENDTIME,
                            LTCprikey,
                            LTCpubkey,
                            OBUpubkx,
                            OBUpubky,
                            LTCStr,
                            ECAStr);
    printf("ECAStr=[%s]\n",ECAStr);

    str_len=HexStringToAsc(ECAStr,asn_arr);
    INFO_PRINT("str_len of asn_arr=[%d]\n",str_len);
    SendbyPost("POST","self-enrollment-certificate",CICVHOST,CICVPORT,asn_arr,str_len,outstr);
    ret=splitRecvPkg(outstr,&serverRespond);
    //printf("recv [%d] arrs!",ret);
    printrespond(&serverRespond);

}

int OBUPrikeySave()
{


}

int OBUPrikeyLoad()
{


}



