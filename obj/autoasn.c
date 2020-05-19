#include "autoasn.h"
#include "common.h"
#include "sm2_sign_and_verify.h"


int SetSubjectInfo(int subjectType,const char *subjectName,SubjectInfo_t *outstr)
{
    int str_len=0;
    outstr->subjectType=subjectType;
    str_len=AscString2HexString((unsigned char *)subjectName,strlen(subjectName),(unsigned char *)outstr->subjectName.buf);
    outstr->subjectName.bufsize=str_len;
    INFO_PRINT("subjectName.buf=[%s]\n",outstr->subjectName.buf);
}


int SetPublicVerifyKey(const int curve,const int ECCPoint,const char *pubkx,const char *pubky,PublicVerifyKey_t *outstr)
{
    int ret=0;
    outstr->ExAttr=0;
    outstr->curve=curve;
    outstr->key.Choice=ECCPoint;
    if(asnxonly==ECCPoint)
        sprintf(outstr->key.MotBaseTypes_ECCPoint_u.sm2_x_only,"%s",pubkx);
         //memcpy(outstr->key.MotBaseTypes_ECCPoint_u.sm2_x_only,pubkx,64);
    else if(asncompressedy0==ECCPoint)
        sprintf(outstr->key.MotBaseTypes_ECCPoint_u.sm2_compressed_y_0,"%s",pubkx);
         //memcpy(outstr->key.MotBaseTypes_ECCPoint_u.sm2_compressed_y_0,pubkx,64);
    else if(asncompressedy1==ECCPoint)
        sprintf(outstr->key.MotBaseTypes_ECCPoint_u.sm2_compressed_y_1,"%s",pubkx);
         //memcpy(outstr->key.MotBaseTypes_ECCPoint_u.sm2_compressed_y_1,pubkx,64);
    else if(asnuncompressedP256==ECCPoint)
    {
        sprintf(outstr->key.MotBaseTypes_ECCPoint_u.sm2_uncompressedP256.x,"%s",pubkx);
        sprintf(outstr->key.MotBaseTypes_ECCPoint_u.sm2_uncompressedP256.y,"%s",pubky);
         //memcpy(outstr->key.MotBaseTypes_ECCPoint_u.sm2_uncompressedP256.x,pubkx,64);
         //memcpy(outstr->key.MotBaseTypes_ECCPoint_u.sm2_uncompressedP256.y,pubky,64);
    }
    
    return ret;
}

int SetSubjectAttributes_PublicVerifyKey_Only(const char *OPTIONAL,int curve,int ECCPoint,const char *pubkx,const char *pubky,SubjectAttribute_t *outstr)
{
    int ret = 0;
    //memcpy(outstr->Optional,OPTIONAL,2);
    sprintf(outstr->Optional,"%s",OPTIONAL);
    if(!strcmp("00",OPTIONAL))
    {
         SetPublicVerifyKey(curve,ECCPoint,pubkx,pubky,&outstr->verificationKey);
    }
    
    return ret;
}


int SetValidityPeriod(const int Choice,const long time_start,const long time_end,MotCert_ValidityPeriod_t *outstr)
{
    int ret = 0;
    
    outstr->Choice=Choice;
    
    if(PR_timeEnd==Choice)
    {
        outstr->MotCert_ValidityPeriod_u.timeEnd=time_end;
    }
    else if(PR_timeStartAndEnd==Choice)
    {
        outstr->MotCert_ValidityPeriod_u.timeStartAndEnd.startValidity=time_start;
        outstr->MotCert_ValidityPeriod_u.timeStartAndEnd.endValidity=time_end;
    }
    else
        ret = -1;

    return ret;   

}

int SetValidityRestriction_ValidityPeriod_Only(const char *OPTIONAL,const int Choice,const long time_start,const long time_end,ValidityRestriction_t *outstr)
{
    int ret = 0;
    //memcpy(outstr->Optional,OPTIONAL,2);
    sprintf(outstr->Optional,"%s",OPTIONAL);
    if(!strcmp("00",OPTIONAL))
    {    
        SetValidityPeriod(Choice,time_start,time_end,&outstr->validityPeriod);
    }
    

    return ret; 


}

int SetTbsCert_CICV(const char *subjectName,const char *pubkx,const char *pubky,const long time_end,TbsCert_t *outstr)
{
    int ret = 0;
    
    SetSubjectInfo(SubjectType_enrollmentCredential,subjectName,&outstr->subjectInfo);
    SetSubjectAttributes_PublicVerifyKey_Only("00",sgdsm2,asnuncompressedP256,pubkx,pubky,&outstr->subjectAttributes);
    SetValidityRestriction_ValidityPeriod_Only("00",PR_timeEnd,0,time_end,&outstr->validityRestrictions);

    return ret;

}


int SetEeEcaCertRequest_CICV_MOT(const char *subjectName,const char *pubkx,const char *pubky,const long time_end,EeEcaCertRequest_t *outstr)
{
    int ret = 0;

    outstr->ExAttr=0;
    outstr->version=1;
    outstr->currentTime=get_CICV_current_time();
    outstr->tbsData.Choice=CScmsCertificateTbs_PR_mot;
    SetTbsCert_CICV(subjectName,pubkx,pubky,time_end,&outstr->tbsData.CScmsCertificateTbs_u.mot);


    return ret;

}

int SetCScmsPDU_CICV_ECA(const char *subjectName,const char *pubkx,const char *pubky,const long time_end,CScmsPDU_t *outstr)
{
    int ret = 0;

    outstr->SPUDversion=1;
    outstr->SPDUChoice=CScmsPDUContent_PR_eca_ee;
    outstr->CScmsPDUContent_u.eca_ee.Choice=EcaEndEntityInterfacePDU_PR_eeEcaCertRequest;

    SetEeEcaCertRequest_CICV_MOT(subjectName,pubkx,pubky,time_end,&outstr->CScmsPDUContent_u.eca_ee.EcaEndEntityInterfacePDU_u.eeEcaCertRequest);

    return ret;
}

int SetSignerInfo_X509(const char *X509,CScmsSecureData_SignerInfo_t *outstr)
{
    int ret = 0;
    
    outstr->SignerInfoChoice = CScmsSecureData_SignerInfo_PR_certificate;
    outstr->CScmsSecureData_SignerInfo_u.certificate.CScmsCertificateChoice=CScmsCertificate_PR_x509;
    outstr->CScmsSecureData_SignerInfo_u.certificate.CScmsCertificate_u.x509.LengthChoice=82;
    
    outstr->CScmsSecureData_SignerInfo_u.certificate.CScmsCertificate_u.x509.x509_Opaque.bufsize=strlen(X509);
    //memcpy(outstr->CScmsSecureData_SignerInfo_u.certificate.CScmsCertificate_u.x509.x509_Opaque.buf,X509,strlen(X509));
    sprintf(outstr->CScmsSecureData_SignerInfo_u.certificate.CScmsCertificate_u.x509.x509_Opaque.buf,"%s",(unsigned char*)X509);


    return ret;
}

int SetSignature(const char *r,const char *s,MotCert_Signature_t *outstr)
{
    int ret = 0;

    outstr->curve = sgdsm2;
    outstr->r.Choice = asnxonly;
    //memcpy(outstr->r.MotBaseTypes_ECCPoint_u.sm2_x_only,r,64+1);
    //memcpy(outstr->s,s,64+1);
    sprintf(outstr->r.MotBaseTypes_ECCPoint_u.sm2_x_only,"%s",r);
    sprintf(outstr->s,"%s",s);
    
    INFO_PRINT("outstr->r = [%s] outstr->s = [%s]\n", outstr->r.MotBaseTypes_ECCPoint_u.sm2_x_only,outstr->s);
    return ret;

}


int SetSignedCertificateRequest(const char *SubjectName,
                                            const long EndTime,
                                            const char *LTC_prikey,
                                            const char *LTC_pubkey,
                                            const char *OBU_pubkeyx,
                                            const char *OBU_pubkeyy,
                                            const char *LTC_CertStr,
                                            SignedCertificateRequest_t *SignedCertRequest)
{
    int ret = 0;
    int str_len = 0;
    int hash_len = 0;

    TbsCert_t *tbscert=NULL;
    unsigned char tbsbuf[2048]={0};
    unsigned char SignedCertReqbuf[2048]={0};
    unsigned char message[128+1]={0};
    unsigned char tbshash[64+1]={0};
    unsigned char ltchash[64+1]={0};
    unsigned char pub_key[128];
    unsigned char r[64+1]={0};
    unsigned char s[64+1]={0};
    SM2_SIGNATURE_STRUCT sm2_sig_out;

    tbscert=&SignedCertRequest->TbsRequest.CScmsPDUContent_u.eca_ee.EcaEndEntityInterfacePDU_u.eeEcaCertRequest.tbsData.CScmsCertificateTbs_u.mot;
    INFO_PRINT("SubjectName =[%s]\n",SubjectName);
    //SetTbsCert_CICV(SubjectName,OBU_pubkeyx,OBU_pubkeyy,EndTime,tbscert);
    SetCScmsPDU_CICV_ECA(SubjectName,OBU_pubkeyx,OBU_pubkeyy,EndTime,&SignedCertRequest->TbsRequest);
    str_len=Encode_CScmsPDU(&SignedCertRequest->TbsRequest,tbsbuf);
    INFO_PRINT("tbsbuf=[%s]\n",tbsbuf);

    
    if(64 != sm3_string_hash_string(tbsbuf,tbshash))
        return -1;
    if(64 != sm3_string_hash_string(LTC_CertStr,ltchash))
        return -1;
    
    DEBUG_PRINT("tbshash=[%s]\n",tbshash);
    DEBUG_PRINT("ltchash=[%s]\n",ltchash);
    
    //memcpy(message,tbshash,64);
    //memcpy(message+64,ltchash,64);
    sprintf(message,"%s%s",tbshash,ltchash);
    
    INFO_PRINT("LTC_pubkey=[%s],message=[%s]\n",LTC_pubkey,message);

    if ( ret = sm2_sign(message,
                        uncompress,
                        g_IDA,
                        LTC_pubkey,
                        LTC_prikey,
                        &sm2_sig_out))
    {
        ERROR_PRINT("Create SM2 signature failed!\n");
        return ret;
    }

    AscString2HexString(sm2_sig_out.r_coordinate,32,r);
    AscString2HexString(sm2_sig_out.s_coordinate,32,s);
    INFO_PRINT("r=[%s],s=[%s]\n",r,s);

    SignedCertRequest->HashId=0;
    
    SetSignerInfo_X509(LTC_CertStr,&SignedCertRequest->SignerInfo);
    SetSignature(r,s,&SignedCertRequest->Signature);
    //INFO_PRINT("s2 = [%s]\n",s);
    INFO_PRINT("s = [%s]\n",SignedCertRequest->Signature.s);

    return ret;

}


int CreatCicvECSecuredMessage(const char *SubjectName,
                                            const long EndTime,
                                            const char *LTC_prikey,
                                            const char *LTC_pubkey,
                                            const char *OBU_pubkeyx,
                                            const char *OBU_pubkeyy,
                                            const char *LTC_CertStr,
                                            unsigned char *outstr)
{
    int ret=0;
    int str_len=0;
    SM2_SIGNATURE_STRUCT sm2_sig_out={0};
    unsigned char outbuf[2048]={0};
    
    //init
    SecuredMessage_t SecuredMessage;

    //SecuredMessage=malloc(sizeof(char)*4096);
    //memset(SecuredMessage,0,sizeof(SecuredMessage));

    SecuredMessage.SecMversion=2;
    SecuredMessage.SecMPlayloadChoice=CScmsSecureData_Payload_PR_signedCertificateRequest;
    SecuredMessage.LengthChoice=82;
    SetSignedCertificateRequest(SubjectName,EndTime,LTC_prikey,LTC_pubkey,OBU_pubkeyx,OBU_pubkeyy,LTC_CertStr,&SecuredMessage.EndEntityMaInterface_Payload_u.SignedCertificateRequest);
    //str_len=Encode_SignedCertificateRequest(&SecuredMessage.EndEntityMaInterface_Payload_u.SignedCertificateRequest,outbuf);
    INFO_PRINT("str_len for SignedCertificateRequest= [%d]\n",str_len);
    ret=Encode_SecuredMessage(&SecuredMessage,outstr);
    

    //free(SecuredMessage);
    //SecuredMessage=NULL;
    return ret;

}



