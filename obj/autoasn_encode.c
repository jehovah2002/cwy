#include "autoasn.h"
#include "common.h"


int Encode_ValidityPeriod(const MotCert_ValidityPeriod_t *MotCertTime,unsigned char *outstr)// 10-18
{
/*
// ValidityPeriod
typedef struct MotCert_ValidityPeriod {
	int Choice;
	union MotCert_ValidityPeriod_u {
		long timeEnd;
		MotCert_TimeStartAndEnd_t	 timeStartAndEnd;
	} MotCert_ValidityPeriod_u;
} MotCert_ValidityPeriod_t;

// TimeStartAndEnd
typedef struct MotCert_TimeStartAndEnd {
	long startValidity;
	long endValidity;
} MotCert_TimeStartAndEnd_t;

*/
    int str_len=0;
    char out_buf[256]={0};
    if(PR_timeEnd==MotCertTime->Choice)
    {
        if(0 < MotCertTime->MotCert_ValidityPeriod_u.timeEnd)
        {
            sprintf(outstr,"%02d%08lX",MotCertTime->Choice,MotCertTime->MotCert_ValidityPeriod_u.timeEnd);
            str_len=2+8;
        }
    }
    else if(PR_timeStartAndEnd==MotCertTime->Choice)
    {
        if((0 < MotCertTime->MotCert_ValidityPeriod_u.timeStartAndEnd.startValidity)&&(0 < MotCertTime->MotCert_ValidityPeriod_u.timeStartAndEnd.endValidity))
        {
            sprintf(outstr,"%02d%08lX%08lX",MotCertTime->Choice,MotCertTime->MotCert_ValidityPeriod_u.timeStartAndEnd.startValidity,MotCertTime->MotCert_ValidityPeriod_u.timeStartAndEnd.endValidity);
            str_len=2+8+8;
        }
    }
    INFO_PRINT("outstr=[%s]\n",outstr);
    return str_len;

}

int Encode_ValidityRestriction(const ValidityRestriction_t *ValidityRestriction,unsigned char *outstr) //4-20
{
/*
// ValidityRestriction

typedef struct ValidityRestriction {
    char Optional[LUint8];
	MotCert_ValidityPeriod_t validityPeriod;
	MotBaseTypes_GeographicRegion_t *region;	// OPTIONAL
} ValidityRestriction_t;

*/
    int str_len=0;
    char out_buf[256]={0};
    if(!strcmp("00",ValidityRestriction->Optional))
    { 
        str_len=Encode_ValidityPeriod(&ValidityRestriction->validityPeriod,out_buf);
        sprintf(outstr,"%s%s",ValidityRestriction->Optional,out_buf);
        str_len=str_len+2;
        
    }
    else if(!strcmp("10",ValidityRestriction->Optional))
    {

    }
    INFO_PRINT("outstr=[%s]\n",outstr);
    return str_len;

}

int Encode_SignECCPoint(const MotBaseTypes_ECCPoint_t *inECCPoint,unsigned char *outstr)//2-130
{
/*

//UncompressedP256 
typedef struct UncompressedP256 {
	char x[64];
	char y[64];
} UncompressedP256_t;
//ECCPoint
typedef struct MotBaseTypes_ECCPoint {
	int Choice;
	union MotBaseTypes_ECCPoint_u {
		char sm2_x_only[64];
		char *sm2_fill;//NULL
		char sm2_compressed_y_0[64];
		char sm2_compressed_y_1[64];
		UncompressedP256_t	 sm2_uncompressedP256;
	} MotBaseTypes_ECCPoint_u;
} MotBaseTypes_ECCPoint_t;
*/
    int str_len=0;
    //char out_buf[256]={0};
    if(asnuncompressedP256==inECCPoint->Choice)
    {
        sprintf(outstr,"%02d%s%s",inECCPoint->Choice,inECCPoint->MotBaseTypes_ECCPoint_u.sm2_uncompressedP256.x,inECCPoint->MotBaseTypes_ECCPoint_u.sm2_uncompressedP256.y);
        str_len=2+64+64;
    }
    else if(asnfill==inECCPoint->Choice)
    {    
        sprintf(outstr,"%02d",inECCPoint->Choice);
        str_len=2;
    }
    else if(asnxonly==inECCPoint->Choice)
    {
        sprintf(outstr,"%02d%s",inECCPoint->Choice,inECCPoint->MotBaseTypes_ECCPoint_u.sm2_x_only);
        str_len=2+64;
    }
    else if(asncompressedy0==inECCPoint->Choice)
    {
        sprintf(outstr,"%02d%s",inECCPoint->Choice,inECCPoint->MotBaseTypes_ECCPoint_u.sm2_compressed_y_0);
        str_len=2+64;
    }
    else if(asncompressedy1==inECCPoint->Choice)
    {
        sprintf(outstr,"%02d%s",inECCPoint->Choice,inECCPoint->MotBaseTypes_ECCPoint_u.sm2_compressed_y_1);
        str_len=2+64;
    }
    INFO_PRINT("outstr=[%s]\n",outstr);
    return str_len;
}

int Encode_SignPublicVerifyKey(const PublicVerifyKey_t *inPublicVerifyKey,unsigned char *outstr)//6-134
{
/* 
//PublicVerifyKey 
typedef struct PublicVerifyKey {
    int ExAttr;//={"00"}; for SEQUENCE ...
    int curve;
    MotBaseTypes_ECCPoint_t  key;
} PublicVerifyKey_t;
*/


    int str_len=0;
    char out_buf[256]={0};
    if(0==inPublicVerifyKey->ExAttr)
    {
        str_len=Encode_SignECCPoint(&inPublicVerifyKey->key,out_buf);
        sprintf(outstr,"%02d%02d%s",inPublicVerifyKey->ExAttr,inPublicVerifyKey->curve,out_buf);
        str_len=str_len+2+2;
    }
    //memcpy(outstr,out_buf,str_len);
    INFO_PRINT("outstr=[%s]\n",outstr);
    return str_len;
}

int Encode_SubjectAttribute(const SubjectAttribute_t *SubjectAttribute,unsigned char *outstr)//8-136
{
/*
typedef struct SubjectAttribute {
    char Optional[LUint8];
	PublicVerifyKey_t verificationKey;
	PublicEncryptionKey_t *encryptionKey;	// OPTIONAL
	MotCert_SubjectAssurance_t *assuranceLevel;// OPTIONAL
	SequenceOfitsAidList_t	*itsAidList;	// OPTIONAL
	SequenceOfitsAidSspList_t *itsAidSspList;	// OPTIONAL
} SubjectAttribute_t;


*/
    int str_len=0;
    char out_buf[256]={0};
    
    if(!strcmp("00",SubjectAttribute->Optional))
    {
        str_len=Encode_SignPublicVerifyKey(&SubjectAttribute->verificationKey,out_buf);
        sprintf(outstr,"%s%s",SubjectAttribute->Optional,out_buf);
        str_len=str_len+2;
    }
    else if(!strcmp("20",SubjectAttribute->Optional))
    {
        //verificationKey
        //encryptionKey
        ;
    }
    INFO_PRINT("outstr=[%s]\n",outstr);
    return str_len;
}



int Encode_SubjectInfo(const SubjectInfo_t *subjectinfo,unsigned char *outstr) //2-34
{
/*
//SubjectInfo 
typedef struct SubjectInfo {
	int subjectType;//=00
	OCTET_STRING_t subjectName;//subjectName 0~32

} SubjectInfo_t;

typedef struct OCTET_STRING {
    int bufsize;
	uint8_t *buf;
} OCTET_STRING_t;

*/
    int str_len=0;
    sprintf(outstr,"%02d%02X%s",subjectinfo->subjectType,subjectinfo->subjectName.bufsize/2,subjectinfo->subjectName.buf);
    str_len=strlen(subjectinfo->subjectName.buf)+2+2;

    INFO_PRINT("outstr=[%s]\n",outstr);
    return str_len;
}

int Encode_TbsCert(const TbsCert_t *TbsCert,unsigned char *outstr)//14-190
{
/*
// TbsCert
typedef struct TbsCert {
	SubjectInfo_t	 subjectInfo;
	SubjectAttribute_t	 subjectAttributes;
	ValidityRestriction_t	 validityRestrictions;
} TbsCert_t;
*/
    int str_len=0;
    int str_len_info=0;
    int str_len_attr=0;
    int str_len_valrest=0;
    char out_buf_info[256]={0};
    char out_buf_attr[256]={0};
    char out_buf_valrest[256]={0};


    str_len_info=Encode_SubjectInfo(&TbsCert->subjectInfo,out_buf_info);
    str_len_attr=Encode_SubjectAttribute(&TbsCert->subjectAttributes,out_buf_attr);
    str_len_valrest=Encode_ValidityRestriction(&TbsCert->validityRestrictions,out_buf_valrest);
    sprintf(outstr,"%s%s%s",out_buf_info,out_buf_attr,out_buf_valrest);
    str_len=str_len_info+str_len_attr+str_len_valrest;

    INFO_PRINT("outstr=[%s]\n",outstr);
    return str_len;

}

int Encode_CScmsCertificateTbs(const CScmsCertificateTbs_t *CertificateTbs,unsigned char *outstr)//16-192
{
/*
// CScmsCertificateTbs
typedef struct CScmsCertificateTbs {
	int Choice;
	union CScmsCertificateTbs_u {
		IeeeCertificateTbs_t	 ieee1609;
		CicvCertificateTbs_t	 cicv;
		TbsCert_t	 mot;
	} CScmsCertificateTbs_u;
} CScmsCertificateTbs_t;

*/
    int str_len=0;
    char out_buf[256]={0};

    if(CScmsCertificateTbs_PR_mot==CertificateTbs->Choice)
    {
        str_len=Encode_TbsCert(&CertificateTbs->CScmsCertificateTbs_u.mot,out_buf);
        sprintf(outstr,"%02d%s",CertificateTbs->Choice,out_buf);
        str_len=str_len+2;
    }


    INFO_PRINT("outstr=[%s]\n",outstr);
    return str_len;
}

int Encode_EeEcaCertRequest(const EeEcaCertRequest_t *EcaEECertReq,unsigned char *outstr)//20-196
{
/* 

//EeEcaCertRequest
typedef struct EeEcaCertRequest {
    int ExAttr;//={"00"}; for SEQUENCE ...
	int version;
	long currentTime;
	CScmsCertificateTbs_t   tbsData;
}EeEcaCertRequest_t;
*/
    int str_len=0;
    char out_buf[256]={0};

    str_len=Encode_CScmsCertificateTbs(&EcaEECertReq->tbsData,out_buf);
    sprintf(outstr,"%02d%02d%08lX%s",EcaEECertReq->ExAttr,EcaEECertReq->version,EcaEECertReq->currentTime,out_buf);
    str_len=str_len+2+2+8;

    INFO_PRINT("outstr=[%s]\n",outstr);
    return str_len;

}
int Encode_EcaEndEntityInterfacePDU(const EcaEndEntityInterfacePDU_t *EcaEEPDU,unsigned char *outstr)//24-200
{
/*
// EcaEndEntityInterfacePDU
typedef struct EcaEndEntityInterfacePDU {
    int Choice;
    union EcaEndEntityInterfacePDU_u {
        EeEcaCertRequest_t   eeEcaCertRequest;
        EcaEeCertResponse_t  ecaEeCertResponse;
        //
        // This type is extensible,
        // possible extensions are below.
        //
    }EcaEndEntityInterfacePDU_u;
} EcaEndEntityInterfacePDU_t;
*/
    int str_len=0;
    char out_buf[256]={0};
    
    str_len=Encode_EeEcaCertRequest(&EcaEEPDU->EcaEndEntityInterfacePDU_u.eeEcaCertRequest,out_buf);
    sprintf(outstr,"%02d%s",EcaEEPDU->Choice,out_buf);
    str_len=str_len+2;

    INFO_PRINT("outstr=[%s]\n",outstr);
    return str_len;
}

int Encode_CScmsPDU(const CScmsPDU_t *CScmsPDU,unsigned char *outstr)//28-204
{
/*
typedef struct {
    int SPUDversion;
    int SPDUChoice;
	union CScmsPDUContent_u {
		EcaEndEntityInterfacePDU_t	 eca_ee;
		EndEntityMaInterfacePDU_t	 ee_ma;
		EndEntityAsInterfacePDU_t	 ee_as;
	} CScmsPDUContent_u;
}CScmsPDU_t;
*/
    int str_len=0;
    char out_buf[256]={0};
    if(CScmsPDUContent_PR_eca_ee==CScmsPDU->SPDUChoice)
    {
        str_len=Encode_EcaEndEntityInterfacePDU(&CScmsPDU->CScmsPDUContent_u.eca_ee,out_buf);
        sprintf(outstr,"%02d%02d%s",CScmsPDU->SPUDversion,CScmsPDU->SPDUChoice,out_buf);
        str_len=str_len+2+2;
    }
    INFO_PRINT("outstr=[%s]\n",outstr);
    return str_len;
}

int Encode_MotCertCertificate(const MotCert_Certificate_t *MotCert,unsigned char *outstr)
{
/*
//Certificate
typedef struct MotCert_Certificate {
	int version;
	IssuerId_t	 issuerId;
	TbsCert_t	 tbs;
	MotCert_Signature_t signature;

} MotCert_Certificate_t;
*/

    int str_len=0;
    
    
    return str_len;

}

int Encode_CScmsCertificate(const CScmsCertificate_t *certificate,unsigned char *outstr)//8-2048
{

/* 
//CScmsCertificate 
typedef struct CScmsCertificate {
	int CScmsCertificateChoice;
	union CScmsCertificate_u {
		MotBaseTypes_Opaque_t	 x509;
		OCTET_STRING_t	 ieee1609;
		OCTET_STRING_t	 cicv;
		MotCert_Certificate_t	 mot;
	} CScmsCertificate_u;
} CScmsCertificate_t;

typedef struct MotBaseTypes_Opaque{
	int  LengthChoice;//82
    OCTET_STRING_t x509_Opaque;
}MotBaseTypes_Opaque_t;

*/
    int str_len=0;
    char out_buf[2048]={0};
    
    if(CScmsCertificate_PR_x509==certificate->CScmsCertificateChoice)
    {
        sprintf(outstr,"%02d%02d%04X%s",certificate->CScmsCertificateChoice, \
            certificate->CScmsCertificate_u.x509.LengthChoice,\
            certificate->CScmsCertificate_u.x509.x509_Opaque.bufsize/2,\
            certificate->CScmsCertificate_u.x509.x509_Opaque.buf);
        str_len=2+2+4+certificate->CScmsCertificate_u.x509.x509_Opaque.bufsize;
    }

    INFO_PRINT("outstr=[%s]\n",outstr);
    return str_len;

}



int Encode_SignerInfo(const CScmsSecureData_SignerInfo_t *SignerInfo,unsigned char *outstr)//10-2048
{
/*
//SignerInfo 
typedef struct CScmsSecureData_SignerInfo {
	int SignerInfoChoice;
	union CScmsSecureData_SignerInfo_u {
		char *self;//NULL
		CScmsCertificate_t	 certificate;
		 //
		 // This type is extensible,
		 / possible extensions are below.
		 //
	} CScmsSecureData_SignerInfo_u;
} CScmsSecureData_SignerInfo_t;
*/
    int str_len=0;
    char out_buf[2048]={0};

    if(CScmsSecureData_SignerInfo_PR_certificate==SignerInfo->SignerInfoChoice)
    {
        str_len=Encode_CScmsCertificate(&SignerInfo->CScmsSecureData_SignerInfo_u.certificate,out_buf);
        sprintf(outstr,"%02d%s",SignerInfo->SignerInfoChoice,out_buf);
        str_len=str_len+2;
    }

    INFO_PRINT("outstr=[%s]\n",outstr);
    return str_len;


}
int Encode_Signature(const MotCert_Signature_t *Signature,unsigned char *outstr)//68-196
{
/*
// Signature
typedef struct MotCert_Signature {
	int curve;
	MotBaseTypes_ECCPoint_t	 r;
	char s[LKey];
} MotCert_Signature_t;

*/
    int str_len=0;
    char out_buf[256]={0};
    

    str_len=Encode_SignECCPoint(&Signature->r,out_buf);
    //printf("Signature->s=[%s]\n",Signature->s);
    sprintf(outstr,"%02d%s%s",Signature->curve,out_buf,Signature->s);
    str_len=str_len+2+64;

    INFO_PRINT("outstr=[%s]\n",outstr);
    return str_len;

}

int Encode_SignedCertificateRequest(const SignedCertificateRequest_t *SignedCertReq,unsigned char *outstr)
{
/*
typedef struct {
	int HashId;
	ScopedCertificateRequest_t TbsRequest;
	CScmsSecureData_SignerInfo_t SignerInfo;
	MotCert_Signature_t Signature;
}SignedCertificateRequest_t;


*/
    int str_len=0;
    int str_len_tbsreq=0;
    int str_len_signerinfo=0;
    int str_len_signature=0;
    char out_buf_tbsreq[1024]={0};
    char out_buf_signerinfo[2048]={0};
    char out_buf_signature[256]={0};


    str_len_tbsreq=Encode_CScmsPDU(&SignedCertReq->TbsRequest,out_buf_tbsreq);
    str_len_signerinfo=Encode_SignerInfo(&SignedCertReq->SignerInfo,out_buf_signerinfo);
    str_len_signature=Encode_Signature(&SignedCertReq->Signature,out_buf_signature);
    sprintf(outstr,"%02d%s%s%s",SignedCertReq->HashId,out_buf_tbsreq,out_buf_signerinfo,out_buf_signature);
    str_len=str_len_tbsreq+str_len_signerinfo+str_len_signature+2;
    INFO_PRINT("outstr=[%s]\n",outstr);
    return str_len;
}


int Encode_SecuredMessage(const SecuredMessage_t *SecuredMessage,unsigned char *outstr)
{

/*
typedef struct {
	int SecMversion;
	int SecMPlayloadChoice;
	int LengthChoice;//82
	int Length;
    union EndEntityMaInterface_Payload_u {
		MotBaseTypes_Opaque_t	            unSecuredData;
		EndEntityMaInterface_SignedData_t	signedData;
		MotSecureData_EncryptedData_t	    encData;
        SignedCertificateRequest_t          SignedCertificateRequest;
	}EndEntityMaInterface_Payload_u;
}SecuredMessage_t;
*/
    int str_len=0;
    char out_buf[4096]={0};
    char buff[64]={0};

    if(EndEntityMaInterface_Payload_PR_SecuredMessage==SecuredMessage->SecMPlayloadChoice)
    {
        str_len=Encode_SignedCertificateRequest(&SecuredMessage->EndEntityMaInterface_Payload_u.SignedCertificateRequest,out_buf);
        INFO_PRINT("SecuredMessage str_len=[%d]\n",str_len);
        sprintf(outstr,"%02d%02d%02d%04X%s",SecuredMessage->SecMversion,SecuredMessage->SecMPlayloadChoice,SecuredMessage->LengthChoice,str_len/2,out_buf);
        str_len=str_len+2+2+4;
    }
    INFO_PRINT("outstr=[%s]\n",outstr);
    return str_len;
}

