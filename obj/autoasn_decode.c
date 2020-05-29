#include "autoasn.h"
#include "common.h"


int Decode_SubjectInfo(const char *instr,SubjectInfo_t *outstruct,char *outstr)
{
    int ret=0;
    char subjectType[4]={0};
    char bufsize[4]={0};
    int length=0;

    snprintf(subjectType,2+1,"%s",instr);
    outstruct->subjectType=atoi(subjectType);
    snprintf(bufsize,2+1,"%s",instr+2);
    length=HexToDec(bufsize);
    outstruct->subjectName.bufsize=length*2;
    snprintf(outstruct->subjectName.buf,length*2+1,"%s",instr+2+2);
    memcpy(outstr,instr+2+2+length*2,strlen(instr+2+2+length*2));
    INFO_PRINT("outstr=[%s]\n",outstr);

    return ret;
}
int Decode_ECCPoint(const char *instr,MotBaseTypes_ECCPoint_t *outstruct,char *outstr)
{
    int ret=0;
    char ECCchoice[4]={0};
    INFO_PRINT("instr=[%s]\n",instr);
    
    snprintf(ECCchoice,2+1,"%s",instr);
    outstruct->Choice=atoi(ECCchoice);
    INFO_PRINT("outstruct->Choice=[%d]\n",outstruct->Choice);
    if(asnxonly==outstruct->Choice)
    {
        snprintf(outstruct->MotBaseTypes_ECCPoint_u.sm2_x_only,64+1,"%s",instr+2);
        memcpy(outstr,instr+2+64,strlen(instr+2+64));
    }
    else if(asncompressedy0==outstruct->Choice)
    {
        snprintf(outstruct->MotBaseTypes_ECCPoint_u.sm2_compressed_y_0,64+1,"%s",instr+2);
        memcpy(outstr,instr+2+64,strlen(instr+2+64));
    }
    else if(asncompressedy1==outstruct->Choice)
    {
        snprintf(outstruct->MotBaseTypes_ECCPoint_u.sm2_compressed_y_1,64+1,"%s",instr+2);
        memcpy(outstr,instr+2+64,strlen(instr+2+64));
    }
    else if(asnuncompressedP256==outstruct->Choice)
    {
        snprintf(outstruct->MotBaseTypes_ECCPoint_u.sm2_uncompressedP256.x,64+1,"%s",instr+2);
        snprintf(outstruct->MotBaseTypes_ECCPoint_u.sm2_uncompressedP256.y,64+1,"%s",instr+2+64);
        memcpy(outstr,instr+2+64+64,strlen(instr+2+64+64));
    }
    INFO_PRINT("outstr=[%s]\n",outstr);
    return ret;
}

int Decode_PublicVerifyKey(const char *instr,PublicVerifyKey_t *outstruct,char *outstr)
{
    int ret=0;
    char ExAttr[4]={0};
    char curve[4]={0};
    INFO_PRINT("instr=[%s]\n",instr);

    snprintf(ExAttr,2+1,"%s",instr);
    snprintf(curve,2+1,"%s",instr+2);
    outstruct->curve=atoi(curve);
    
    Decode_ECCPoint(instr+2+2,&outstruct->key,outstr);
    INFO_PRINT("outstr=[%s]\n",outstr);
    return ret;
}


int Decode_SubjectAttribute(const char *instr,SubjectAttribute_t *outstruct,char *outstr)
{
    int ret=0;
    //char Optional[4]={0};
    char buff_arr1[4096]={0};
    char assuranceLevel[4]={0};
    snprintf(outstruct->Optional,2+1,"%s",instr);
    INFO_PRINT("outstruct->Optional=[%s]\n",outstruct->Optional);
    if(!(strcmp("20",outstruct->Optional)))
    {
        Decode_PublicVerifyKey(instr+2,&outstruct->verificationKey,buff_arr1);
        snprintf(outstruct->assuranceLevel,2+1,"%s",buff_arr1);
        memcpy(outstr,buff_arr1+2,strlen(buff_arr1+2));
    }
    else if(!(strcmp("00",outstruct->Optional)))
    {
        Decode_PublicVerifyKey(instr+2,&outstruct->verificationKey,outstr);

    }
    INFO_PRINT("outstr=[%s]\n",outstr);

    return ret;
}


int Decode_ValidityPeriod(const char *instr,MotCert_ValidityPeriod_t *outstruct,char *outstr)
{
    int ret=0;
    char Choice[4]={0};
    char startValidity[8+1]={0};
    char endValidity[8+1]={0};
    
    snprintf(Choice,2+1,"%s",instr);
    outstruct->Choice=atoi(Choice);
    if(PR_timeEnd==outstruct->Choice)
    {
        snprintf(endValidity,8+1,"%s",instr+2);
        outstruct->MotCert_ValidityPeriod_u.timeEnd=HexToDec(endValidity);
        memcpy(outstr,instr+2+8,strlen(instr+2+8));

    }
    else if(PR_timeStartAndEnd==outstruct->Choice)
    {
        snprintf(startValidity,8+1,"%s",instr+2);
        outstruct->MotCert_ValidityPeriod_u.timeStartAndEnd.startValidity=HexToDec(startValidity);
        snprintf(endValidity,8+1,"%s",instr+2+8);
        outstruct->MotCert_ValidityPeriod_u.timeStartAndEnd.endValidity=HexToDec(endValidity);
        memcpy(outstr,instr+2+8+8,strlen(instr+2+8+8));
    }
    INFO_PRINT("outstr=[%s]\n",outstr);
    return ret;
}

int Decode_ValidityRestriction(const char *instr,ValidityRestriction_t *outstruct,char *outstr)
{
    int ret=0;
    

    snprintf(outstruct->Optional,2+1,"%s",instr);
    //DEBUG_PRINT("Optional = [%s]\n",outstruct->Optional);
    if(!(strcmp("00",outstruct->Optional)))
    {
        Decode_ValidityPeriod(instr+2,&outstruct->validityPeriod,outstr);
    }


    return ret;
}




int Decode_TbsCert(const char *instr,TbsCert_t *outstruct,char *outstr)
{
    int ret=0;
    char buff_arr1[4096]={0};
    char buff_arr2[4096]={0};

    DEBUG_PRINT("instr = [%s]\n",instr);
    Decode_SubjectInfo(instr,&outstruct->subjectInfo,buff_arr1);
    DEBUG_PRINT("Decode_SubjectInfo outstr=[%s]\n",buff_arr1);
    Decode_SubjectAttribute(buff_arr1,&outstruct->subjectAttributes,buff_arr2);
    DEBUG_PRINT("Decode_SubjectAttribute outstr=[%s]\n",buff_arr2);
    Decode_ValidityRestriction(buff_arr2,&outstruct->validityRestrictions,outstr);
    DEBUG_PRINT("Decode_ValidityRestriction outstr=[%s]\n",outstr);


    return ret;

}

int Decode_Signature(const char *instr,MotCert_Signature_t *outstruct,char *outstr)
{
    //DEBUG_PRINT("instr = [%s]\n",instr);
    int ret=0;
    char curve[4]={0};
    char buff_arr1[4096]={0};

    snprintf(curve,2+1,"%s",instr);
    outstruct->curve=atoi(curve);

    Decode_ECCPoint(instr+2,&outstruct->r,buff_arr1);
    snprintf(outstruct->s,64+1,"%s",buff_arr1);
    memcpy(outstr,buff_arr1+64,strlen(buff_arr1+64));
    DEBUG_PRINT("r=[%s]\n",outstruct->r.MotBaseTypes_ECCPoint_u.sm2_x_only);
    DEBUG_PRINT("s=[%s]\n",outstruct->s);

    return ret;
}

int Decode_CertificateDigest(const char *instr,MotCert_CertificateDigest_t *outstruct,char *outstr)
{
    int ret=0;
    char algorithm[4]={0};

    snprintf(algorithm,2+1,"%s",instr);
    outstruct->algorithm=atoi(algorithm);
    snprintf(outstruct->digest,16+1,"%s",instr+2);
    memcpy(outstr,instr+2+16,strlen(instr+2+16));

    return ret;

}


int Decode_IssuerId(const char *instr,IssuerId_t *outstruct,char *outstr)
{
    int ret=0;
    char IssuerIdChoice[4]={0};

    snprintf(IssuerIdChoice,2+1,"%s",instr);
    outstruct->IssuerIdChoice=atoi(IssuerIdChoice);
    Decode_CertificateDigest(instr+2,&outstruct->IssuerId_u.certificateDigest,outstr);
    
    return ret;
}

int Decode_MotCert_Certificate(const char *instr,MotCert_Certificate_t *outstruct,char *outstr)
{
    int ret=0;
    char version[4]={0};
    char buff_arr1[4096]={0};
    char buff_arr2[4096]={0};
    char tmp[4096]={0};

    INFO_PRINT("instr = [%s]\n",instr);
    snprintf(version,2+1,"%s",instr);
    outstruct->version=atoi(version);
    Decode_IssuerId(instr+2,&outstruct->issuerId,buff_arr1);
    DEBUG_PRINT("Decode_IssuerId outstr=[%s]\n",buff_arr1);
    Decode_TbsCert(buff_arr1,&outstruct->tbs,buff_arr2);
    DEBUG_PRINT("Decode_TbsCert outstr=[%s]\n",buff_arr2);
    Decode_Signature(buff_arr2,&outstruct->signature,outstr);
    DEBUG_PRINT("Decode_Signature outstr=[%s]\n",outstr);

    //printf("\n\ninstr-outstr=[%ld]\n\n",strlen(instr)-strlen(outstr));
    snprintf(tmp,strlen(instr)-strlen(outstr)+1,"%s",instr);

    DEBUG_PRINT("Certificate = [%s]\n",tmp);

    return ret;
}


int Decode_CScmsCertificate(const char *instr,CScmsCertificate_t *outstruct,char *outstr)
{
    int ret=0;
    char CertificateChoice[4]={0};

    INFO_PRINT("instr = [%s]\n",instr);
    snprintf(CertificateChoice,2+1,"%s",instr);
    outstruct->CScmsCertificateChoice=atoi(CertificateChoice);
    if(CScmsCertificate_PR_mot==outstruct->CScmsCertificateChoice)
    {
        Decode_MotCert_Certificate(instr+2,&outstruct->CScmsCertificate_u.mot,outstr);
    }
    
    return ret;
}


int Decode_EeEcaCertResponse_CICV_MOT(const char *instr,EcaEeCertResponse_t *outstruct,char *outstr)
{
    int ret=0;
    char version[4]={0};
    char buff_arr1[4096]={0};
    char buff_arr2[4096]={0};
    
    snprintf(outstruct->Optional,2+1,"%s",instr);
    snprintf(version,2+1,"%s",instr+2);
    outstruct->version=atoi(version);
    snprintf(outstruct->requestHash,16+1,"%s",instr+2+2);

    if(!(strcmp("00",outstruct->Optional)))
    {
        Decode_CScmsCertificate(instr+2+2+16,&outstruct->ecaCert,buff_arr1);
        Decode_CScmsCertificate(buff_arr1,&outstruct->enrollmentCert,outstr);
    }

    return ret;
}

int Decode_EEInterfacePDU(const char *instr,EcaEndEntityInterfacePDU_t *outstruct,char *outstr)
{
    int ret=0;
    char Choice[4]={0};

    snprintf(Choice,2+1,"%s",instr);
    outstruct->Choice=atoi(Choice);
    if(EcaEndEntityInterfacePDU_PR_eeEcaCertRequest==outstruct->Choice)
    {

    }
    else if(EcaEndEntityInterfacePDU_PR_ecaEeCertResponse==outstruct->Choice)
    {
        Decode_EeEcaCertResponse_CICV_MOT(instr+2,&outstruct->EcaEndEntityInterfacePDU_u.ecaEeCertResponse,outstr);
    }


    return ret;
}
int Decode_CScmsPDU(const char *instr,CScmsPDU_t *outstruct)
{
    int ret=0;
    char SPUDversion[4]={0};
    char SPDUChoice[4]={0};
    char CScmsPDU_outstr[4096]={0};

    snprintf(SPUDversion,2+1,"%s",instr);
    outstruct->SPUDversion=atoi(SPUDversion);
    snprintf(SPDUChoice,2+1,"%s",instr+2);
    outstruct->SPDUChoice=atoi(SPDUChoice);
    if(CScmsPDUContent_PR_eca_ee==outstruct->SPDUChoice)
    {
        Decode_EEInterfacePDU(instr+2+2,&outstruct->CScmsPDUContent_u.eca_ee,CScmsPDU_outstr);
    }
    else if(CScmsPDUContent_PR_ee_ma==outstruct->SPDUChoice)
    {

    }
    else if(CScmsPDUContent_PR_ee_as==outstruct->SPDUChoice)
    {

    }
    

    return ret;
}

int Decode_TBSData(const char *instr,MotSecureData_TBSData_t *outstruct,char *outstr)
{
    int ret=0;

    char lengthtype[4]={0};
    char length[4+1]={0};
    
    snprintf(outstruct->TbsDataOptional,2+1,"%s",instr);
    snprintf(lengthtype,2+1,"%s",instr+2);
    snprintf(length,4+1,"%s",instr+2+2);
    outstruct->data.bufsize=HexToDec(length);
    snprintf(outstruct->data.buf,outstruct->data.bufsize*2+1,"%s",instr+2+2+4);
    Decode_CScmsPDU(outstruct->data.buf,&ScopedEeEnrollmentCertResponse);

    memcpy(outstr,instr+2+2+4+outstruct->data.bufsize*2,strlen(instr+2+2+4+outstruct->data.bufsize*2));

    return ret;
}


int Decode_EESignedData(const char *instr,EndEntityMaInterface_SignedData_t *outstruct,char *outstr)
{
    int ret=0;
    char SignerInfoChoice[4]={0};
    char buff_arr1[4096]={0};
    char buff_arr2[4096]={0};
    DEBUG_PRINT("instr = [%s]\n",instr);

    snprintf(SignerInfoChoice,2+1,"%s",instr);
    outstruct->signer.SignerInfoChoice=atoi(SignerInfoChoice);//81

    Decode_CScmsCertificate(instr+2,&outstruct->signer.CScmsSecureData_SignerInfo_u.certificate,buff_arr1);
    DEBUG_PRINT("Decode_CScmsCertificate outstr=[%s]\n",buff_arr1);
    Decode_TBSData(buff_arr1,&outstruct->tbs,buff_arr2);
    DEBUG_PRINT("Decode_TBSData outstr=[%s]\n",buff_arr2);
    Decode_Signature(buff_arr2,&outstruct->sign,outstr);
    DEBUG_PRINT("Decode_Signature outstr=[%s]\n",outstr);

    return ret;
}


int Decode_SecuredMessage(const char *instr,SecuredMessage_t *outstruct,char *outstr)
{
    char version[4]={0};
    char choice[4]={0};
    int ret=0;
    
    snprintf(version,2+1,"%s",instr);
    outstruct->SecMversion=atoi(version);
    snprintf(choice,2+1,"%s",instr+2);
    outstruct->SecMPlayloadChoice=atoi(choice);
    
    DEBUG_PRINT("version=[%s] choice=[%s]\n",version,choice);
    DEBUG_PRINT("SecMversion=[%d] SecMPlayloadChoice=[%d]\n",outstruct->SecMversion,outstruct->SecMPlayloadChoice);

    if(CScmsSecureData_Payload_PR_signedData==outstruct->SecMPlayloadChoice)
    {
        Decode_EESignedData(instr+4,&outstruct->EndEntityMaInterface_Payload_u.signedData,outstr);
    }

    return ret;
}


