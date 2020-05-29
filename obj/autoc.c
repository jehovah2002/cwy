#include "autoc.h"
#include "common.h"
#include "autoasn.h"
#include "network.h"
#include "sm2_sign_and_verify.h"


CScmsPDU_t ScopedEeEnrollmentCertResponse;

char *ICA="028100D961EE6A61F09AC50812433D434E2C434E3D436963764D6F744943412000008391771D107BDEAA9D249747F3146B7EFBB1D5A4D256B8A32E010715FC6C125D700000811D2579832E143D830080BDDB05D2B23908E5D0EFC4D6FA679FFE9C401FCD7DE49970C8492FAEBA8897022356BE27A69D28D9A1092D56328A8E761858ED74095C973601CD7F5719F43A4F";



int Auto_ECA(const char *Subjectname,const char *LTCprikey,const char *LTCpubkey,const char *OBUpubkx,const char *OBUpubky,const char *LTCStr)
{
    char ECAStr[4096]={0};
    char asn_arr[4096]={0};
    char outstr[4096]={0};
    int str_len=0;
    int ret=0;
    int error_code;
    
    CicvserverRespond_t serverRespond;
    SecuredMessage_t outstruct;
    char *eca_r=NULL;
    char *eca_s=NULL;
    char *ec_r=NULL;
    char *ec_s=NULL;
    char message[128+1]={0};
    char tbshash[64+1]={0};
    char certhash[64+1]={0};
    char ecaout[1024]={0};
    char ecatbsout[1024]={0};
    char ecout[1024]={0};
    char ectbsout[1024]={0};
    int ecpubkey_type=0;
    char *ecpubkeyx=NULL;

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

    memset(outstr,0,sizeof(outstr));
    Decode_SecuredMessage(serverRespond.str,&outstruct,outstr);

    Encode_MotCertificate(&ScopedEeEnrollmentCertResponse.CScmsPDUContent_u.eca_ee.EcaEndEntityInterfacePDU_u.ecaEeCertResponse.ecaCert.CScmsCertificate_u.mot,ecaout);
    DEBUG_PRINT("eca=[%s]\n",ecaout);
    
    //eca tbs
    Encode_TbsCert(&ScopedEeEnrollmentCertResponse.CScmsPDUContent_u.eca_ee.EcaEndEntityInterfacePDU_u.ecaEeCertResponse.ecaCert.CScmsCertificate_u.mot.tbs,ecatbsout);
    DEBUG_PRINT("eca tbs=[%s]\n",ecatbsout);
    //eca r,s
    //r
    eca_r=ScopedEeEnrollmentCertResponse.CScmsPDUContent_u.eca_ee.EcaEndEntityInterfacePDU_u.ecaEeCertResponse.ecaCert.CScmsCertificate_u.mot.signature.r.MotBaseTypes_ECCPoint_u.sm2_x_only;
    //s
    eca_s=ScopedEeEnrollmentCertResponse.CScmsPDUContent_u.eca_ee.EcaEndEntityInterfacePDU_u.ecaEeCertResponse.ecaCert.CScmsCertificate_u.mot.signature.s;

    //ec tbs
   
    

    sm3_string_hash_string(ecatbsout,tbshash);
    sm3_string_hash_string(ICA,certhash);
    DEBUG_PRINT("==eca== tbshash=[%s], certhash = [%s] bytes.\n", tbshash,certhash);

    sprintf(message,"%s%s",tbshash,certhash);
    DEBUG_PRINT("message=[%s] .\n",message);
    if ( error_code = sm2_verify(message,
									compressy1,
									g_IDA,
									g_ICApubkey,
									eca_r,
									eca_s))
	{
		ERROR_PRINT("Verify ECA signature failed! [%d]\n",error_code);
		return error_code;
	}
    else
        printf("Verify ECA signature Success! \n");
                                    
    Encode_MotCertificate(&ScopedEeEnrollmentCertResponse.CScmsPDUContent_u.eca_ee.EcaEndEntityInterfacePDU_u.ecaEeCertResponse.enrollmentCert.CScmsCertificate_u.mot,ecout);
    DEBUG_PRINT("ec=[%s]\n",ecout);
    
    Encode_TbsCert(&ScopedEeEnrollmentCertResponse.CScmsPDUContent_u.eca_ee.EcaEndEntityInterfacePDU_u.ecaEeCertResponse.enrollmentCert.CScmsCertificate_u.mot.tbs,ectbsout);
    DEBUG_PRINT("ec tbs=[%s]\n",ectbsout);
    //ec r,s
    //r
    ec_r=ScopedEeEnrollmentCertResponse.CScmsPDUContent_u.eca_ee.EcaEndEntityInterfacePDU_u.ecaEeCertResponse.enrollmentCert.CScmsCertificate_u.mot.signature.r.MotBaseTypes_ECCPoint_u.sm2_x_only;
    //s
    ec_s=ScopedEeEnrollmentCertResponse.CScmsPDUContent_u.eca_ee.EcaEndEntityInterfacePDU_u.ecaEeCertResponse.enrollmentCert.CScmsCertificate_u.mot.signature.s;

    //ERROR_PRINT("eca r=[%s]\n eca s=[%s]\n ec r=[%s]\n ec s=[%s]\n",eca_r,eca_s,ec_r,ec_s);
    memset(tbshash,0,sizeof(tbshash));
    memset(certhash,0,sizeof(certhash));
    memset(message,0,sizeof(message));
    sm3_string_hash_string(ectbsout,tbshash);
    sm3_string_hash_string(ecaout,certhash);
    DEBUG_PRINT("==ec== tbshash=[%s], certhash = [%s] bytes.\n", tbshash,certhash);

    sprintf(message,"%s%s",tbshash,certhash);
    DEBUG_PRINT("message=[%s] .\n",message);

    ecpubkey_type=ScopedEeEnrollmentCertResponse.CScmsPDUContent_u.eca_ee.EcaEndEntityInterfacePDU_u.ecaEeCertResponse.ecaCert.CScmsCertificate_u.mot.tbs.subjectAttributes.verificationKey.key.Choice-asnxonly;
    ecpubkeyx=ScopedEeEnrollmentCertResponse.CScmsPDUContent_u.eca_ee.EcaEndEntityInterfacePDU_u.ecaEeCertResponse.ecaCert.CScmsCertificate_u.mot.tbs.subjectAttributes.verificationKey.key.MotBaseTypes_ECCPoint_u.sm2_compressed_y_1;
    DEBUG_PRINT("type=[%d],key=[%s],keyy_1=[%s]\n",ecpubkey_type,ecpubkeyx,ScopedEeEnrollmentCertResponse.CScmsPDUContent_u.eca_ee.EcaEndEntityInterfacePDU_u.ecaEeCertResponse.ecaCert.CScmsCertificate_u.mot.tbs.subjectAttributes.verificationKey.key.MotBaseTypes_ECCPoint_u.sm2_compressed_y_1);
    if ( error_code = sm2_verify(message,
									ecpubkey_type,
									g_IDA,
									ecpubkeyx,
									ec_r,
									ec_s))
	{
		ERROR_PRINT("Verify EC signature failed! [%d]\n",error_code);
		return error_code;
	}
    else
        printf("Verify EC signature Success!\n");
    return ret;
}

int OBUPrikeySave()
{


}

int OBUPrikeyLoad()
{


}



